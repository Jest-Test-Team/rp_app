//! WireGuard key handling and client configuration.
//!
//! Client private keys are generated here, printed once, and never stored.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rp_schema::Config;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::vpn::{wg_peer_addr, WG_KEY_PATH};

pub struct KeyPair {
    pub private: String,
    pub public: String,
}

pub fn generate() -> KeyPair {
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    KeyPair { private: B64.encode(secret.to_bytes()), public: B64.encode(public.as_bytes()) }
}

/// Public key for a base64 private key (as written by `wg genkey`).
pub fn public_from_private(private_b64: &str) -> Result<String, String> {
    let bytes = B64.decode(private_b64.trim()).map_err(|e| format!("bad key encoding: {e}"))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "key must be 32 bytes".to_string())?;
    Ok(B64.encode(PublicKey::from(&StaticSecret::from(arr)).as_bytes()))
}

/// Lowest unused host number (2 = first client; 1 is the server).
pub fn next_free_host(cfg: &Config) -> Option<u32> {
    let w = &cfg.vpn.as_ref()?.wireguard;
    let max = (1u64 << (32 - w.subnet.prefix_len())) - 2;
    (2..=max as u32).find(|h| !w.peers.iter().any(|p| p.host == *h))
}

pub fn client_config(cfg: &Config, host: u32, client_private: &str, server_public: &str) -> String {
    let w = &cfg.vpn.as_ref().expect("vpn").wireguard;
    let endpoint = w.endpoint.as_deref().unwrap_or("<PUBLIC_HOST>:51820");
    format!(
        "[Interface]\nPrivateKey = {client_private}\nAddress = {}/32\nDNS = {}\n\n\
         [Peer]\nPublicKey = {server_public}\nEndpoint = {endpoint}\n\
         # All traffic, including IPv6, goes through the tunnel so nothing leaks.\n\
         AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
        wg_peer_addr(cfg, host),
        w.client_dns
    )
}

pub fn peer_toml(name: &str, public: &str, host: u32) -> String {
    format!(
        "[[vpn.wireguard.peers]]\nname = \"{name}\"\npublic_key = \"{public}\"\nhost = {host}\n"
    )
}

pub const SERVER_KEY_PATH: &str = WG_KEY_PATH;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{parse, valid_wg_key};

    #[test]
    fn generated_keys_are_valid_and_consistent() {
        let k = generate();
        assert!(valid_wg_key(&k.private) && valid_wg_key(&k.public));
        assert_eq!(public_from_private(&k.private).unwrap(), k.public);
        assert_ne!(generate().private, k.private);
        assert!(public_from_private("not base64!").is_err());
    }

    #[test]
    fn client_config_routes_everything_and_next_host_skips_used() {
        let cfg = parse(
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n[vpn]\nmode = \"wireguard\"\n\
             [vpn.wireguard]\nendpoint = \"vpn.example.org:51820\"\n\
             [[vpn.wireguard.peers]]\nname = \"a\"\npublic_key = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\nhost = 2\n",
        )
        .unwrap();
        assert_eq!(next_free_host(&cfg), Some(3));
        let c = client_config(&cfg, 3, "PRIV", "PUB");
        assert!(c.contains("Address = 10.88.0.3/32")); // rp-probe:allow
        assert!(c.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(c.contains("Endpoint = vpn.example.org:51820"));
        let toml = peer_toml("b", "PUB", 3);
        assert!(toml.starts_with("[[vpn.wireguard.peers]]"));
    }
}
