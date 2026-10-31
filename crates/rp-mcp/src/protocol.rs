//! The subset of the Model Context Protocol this server speaks (JSON-RPC 2.0):
//! initialize, notifications/initialized, ping, tools/list, tools/call.

use rp_policy::auth::Principal;
use serde_json::{json, Value};

use crate::tools::{self, Dispatcher, UNTRUSTED_NOTE};

pub const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;

fn error(id: Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
}

fn ok(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// Handle one raw message. Returns None for notifications (no reply).
pub async fn handle_raw(d: &Dispatcher, who: &Principal, raw: &str) -> Option<Value> {
    let msg: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Some(error(Value::Null, PARSE_ERROR, "parse error")),
    };
    if msg.is_array() {
        return Some(error(Value::Null, INVALID_REQUEST, "batch requests are not supported"));
    }
    handle(d, who, &msg).await
}

pub async fn handle(d: &Dispatcher, who: &Principal, msg: &Value) -> Option<Value> {
    if msg.get("jsonrpc") != Some(&json!("2.0")) {
        return Some(error(
            msg.get("id").cloned().unwrap_or(Value::Null),
            INVALID_REQUEST,
            "jsonrpc must be \"2.0\"",
        ));
    }
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let Some(id) = msg.get("id").cloned() else {
        // Notification (e.g. notifications/initialized): never answered.
        return None;
    };
    if !(id.is_string() || id.is_i64() || id.is_u64()) {
        return Some(error(Value::Null, INVALID_REQUEST, "id must be a string or integer"));
    }
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let reply = match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
            let version =
                if PROTOCOL_VERSIONS.contains(&asked) { asked } else { PROTOCOL_VERSIONS[0] };
            ok(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "rp-mcp", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": format!(
                        "Tools for observing a home edge gateway. Privileged tools only create requests \
                         that a person must approve on the device. {UNTRUSTED_NOTE}"
                    ),
                }),
            )
        }
        "ping" => ok(id, json!({})),
        "tools/list" => ok(id, tools::list_json()),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(error(id, INVALID_PARAMS, "params.name is required"));
            };
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            match d.call(who, name, &args).await {
                Ok(v) => ok(
                    id,
                    json!({
                        "content": [{"type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default()}],
                        "structuredContent": v,
                        "isError": false,
                    }),
                ),
                // Tool failures (denials included) are results, not protocol errors,
                // so the model sees why the call was refused.
                Err(e) => {
                    ok(id, json!({"content": [{"type": "text", "text": e.0}], "isError": true}))
                }
            }
        }
        _ => error(id, METHOD_NOT_FOUND, "method not found"),
    };
    Some(reply)
}
