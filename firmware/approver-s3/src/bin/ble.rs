//! BLE transport for the approval key (the console app relays the gateway's
//! `ASK` and the key's `DECIDE` over its own connection to the gateway).
//!
//! One GATT service with two characteristics carrying rp-wire *lines*:
//! the phone writes to `rx`, the key notifies on `tx`. Lines are sent in
//! chunks of at most [`CHUNK`] bytes and end with `\n`, so nothing depends on
//! the negotiated MTU. Over BLE the key only answers `HELLO`, `INFO`, `ASK`
//! and `CANCEL`: no profile switches, no console, no settings.
//!
//! Integrity does not depend on the link: the gateway checks the Ed25519
//! signature, its own one-time nonce and the action digest.

use bt_hci::controller::ExternalController;
use embassy_futures::join::join;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
use embassy_sync::channel::Channel;
use esp_radio::ble::controller::BleConnector;
use rp_wire::HostMsg;
use trouble_host::prelude::*;

pub type Line = heapless::String<{ rp_wire::MAX_LINE + 2 }>;

/// Lines received over BLE (already filtered), for the main loop.
pub static BLE_IN: Channel<CriticalSectionRawMutex, Line, 4> = Channel::new();
/// Lines for the connected phone.
pub static BLE_OUT: Channel<CriticalSectionRawMutex, Line, 8> = Channel::new();

pub const CHUNK: usize = 20;

#[gatt_server(mutex_type = NoopRawMutex)]
struct Server {
    key: KeyService,
}

/// rp approval key service (custom 128-bit UUIDs).
#[gatt_service(uuid = "5270b001-7270-4b65-7900-000000000000")]
struct KeyService {
    /// Phone → key: rp-wire line chunks.
    #[characteristic(uuid = "5270b001-7270-4b65-7900-000000000001", write)]
    rx: heapless09::Vec<u8, 64>,
    /// Key → phone: rp-wire line chunks.
    #[characteristic(uuid = "5270b001-7270-4b65-7900-000000000002", notify)]
    tx: heapless09::Vec<u8, CHUNK>,
}

/// The only requests a phone may send.
pub fn allowed_over_ble(m: &HostMsg) -> bool {
    matches!(m, HostMsg::Hello | HostMsg::Info | HostMsg::Ask { .. } | HostMsg::Cancel)
}

fn line_from(s: &str) -> Line {
    let mut l = Line::new();
    let _ = l.push_str(s);
    l
}

/// Run the BLE side forever: advertise as `name`, serve one phone at a time.
pub async fn run(bt: esp_hal::peripherals::BT<'static>, name: &'static str, addr: [u8; 6]) {
    let transport = match BleConnector::new(bt, Default::default()) {
        Ok(t) => t,
        Err(_) => return core::future::pending().await,
    };
    let controller: ExternalController<_, 20> = ExternalController::new(transport);
    let mut resources: HostResources<_, DefaultPacketPool, 1, 1> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(Address::random(addr)).build();
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();
    let Ok(server) = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name,
        appearance: &appearance::UNKNOWN,
    })) else {
        return core::future::pending().await;
    };
    let _ = join(runner.run(), async {
        loop {
            let _ = serve_one(&mut peripheral, &server, name).await;
        }
    })
    .await;
}

async fn serve_one<'v, C: Controller>(
    peripheral: &mut Peripheral<'v, C, DefaultPacketPool>,
    server: &'v Server<'_>,
    name: &str,
) -> Result<(), BleHostError<C::Error>> {
    let mut adv = [0u8; 31];
    let adv_len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteLocalName(name.as_bytes()),
        ],
        &mut adv[..],
    )?;
    let advertiser = peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected { adv_data: &adv[..adv_len], scan_data: &[] },
        )
        .await?;
    let conn = advertiser.accept().await?.with_attribute_server(server)?;
    // A new phone starts clean.
    while BLE_OUT.try_receive().is_ok() {}
    let mut inbuf: heapless::Vec<u8, { rp_wire::MAX_LINE + 2 }> = heapless::Vec::new();
    loop {
        match select(conn.next(), BLE_OUT.receive()).await {
            Either::First(GattConnectionEvent::Disconnected { .. }) => return Ok(()),
            Either::First(GattConnectionEvent::Gatt { event }) => {
                if let GattEvent::Write(w) = &event {
                    if w.handle() == server.key.rx.handle {
                        if let Ok(data) = w.value(&server.key.rx) {
                            for &b in data.iter() {
                                if b == b'\n' {
                                    handle_line(&inbuf);
                                    inbuf.clear();
                                } else if inbuf.push(b).is_err() {
                                    inbuf.clear(); // overlong: drop it
                                }
                            }
                        }
                    }
                }
                if let Ok(reply) = event.accept() {
                    reply.send().await;
                }
            }
            Either::First(_) => {}
            Either::Second(line) => {
                let mut bytes: heapless::Vec<u8, { rp_wire::MAX_LINE + 3 }> = heapless::Vec::new();
                let _ = bytes.extend_from_slice(line.as_bytes());
                let _ = bytes.push(b'\n');
                for chunk in bytes.chunks(CHUNK) {
                    let mut v: heapless09::Vec<u8, CHUNK> = heapless09::Vec::new();
                    let _ = v.extend_from_slice(chunk);
                    if server.key.tx.notify(&conn, &v, false).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

fn handle_line(bytes: &[u8]) {
    let text = core::str::from_utf8(bytes).unwrap_or("").trim_end_matches('\r');
    match HostMsg::parse(text) {
        Some(m) if allowed_over_ble(&m) => {
            let _ = BLE_IN.try_send(line_from(text));
        }
        _ => {
            let _ = BLE_OUT.try_send(line_from("ERR not allowed over BLE"));
        }
    }
}
