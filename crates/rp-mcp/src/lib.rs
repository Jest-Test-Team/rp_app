//! rp-mcp: an MCP server for the rp gateway. Every tool call passes through
//! rp-policy (capabilities, rate limit, strict arguments, audit) before it
//! reaches rp-agent, and privileged tools only create approval requests.

pub mod protocol;
pub mod tools;
