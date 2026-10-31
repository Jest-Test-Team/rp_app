//! The `agent` module: run rp-agent (and rp-mcp when `[mcp]` is configured)
//! as sandboxed services.

use rp_schema::Config;

use crate::files::{ManagedFile, HEADER};
use crate::module::{Module, Step};

pub const AGENT_UNIT: &str = "/etc/systemd/system/rp-agent.service";
pub const MCP_UNIT: &str = "/etc/systemd/system/rp-mcp.service";

pub struct Agent;

fn agent_unit(cfg: &Config) -> String {
    let a = cfg.agent.clone().unwrap_or_default();
    format!(
        "# {HEADER}
[Unit]
Description=rp edge agent (read-only observation API)
After=network-online.target rp-firewall.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/rp-agent --config /etc/rp/rp.toml run
Restart=on-failure
RestartSec=2
# Root only to read root-owned sources (conntrack, the DNS event DB);
# everything else is taken away. It never changes network state.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={state}
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
MemoryMax=64M

[Install]
WantedBy=multi-user.target
",
        state = a.state_dir
    )
}

fn mcp_unit(cfg: &Config) -> String {
    let m = cfg.mcp.as_ref().expect("mcp config");
    format!(
        "# {HEADER}
[Unit]
Description=rp MCP server (tools for AI clients, enforced by rp-policy)
After=rp-agent.service
Wants=rp-agent.service

[Service]
# Secrets are handed over as credentials, readable only by this service.
LoadCredential=agent-token:{token}
LoadCredential=clients:{clients}
Environment=RP_MCP_AGENT_TOKEN_FILE=%d/agent-token
Environment=RP_MCP_CLIENTS_FILE=%d/clients
ExecStart=/usr/local/bin/rp-mcp --config /etc/rp/rp.toml
Restart=on-failure
RestartSec=2
DynamicUser=yes
StateDirectory=rp-mcp
CapabilityBoundingSet=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
MemoryMax=64M

[Install]
WantedBy=multi-user.target
",
        token = m.agent_token_file,
        clients = m.clients_file,
    )
}

impl Module for Agent {
    fn name(&self) -> &'static str {
        "agent"
    }

    fn enabled(&self, cfg: &Config) -> Result<(), String> {
        cfg.agent.as_ref().map(|_| ()).ok_or_else(|| "no [agent] section in the config".into())
    }

    fn render(&self, cfg: &Config) -> Vec<ManagedFile> {
        if cfg.agent.is_none() {
            return vec![];
        }
        let mut f = vec![ManagedFile::new(AGENT_UNIT, 0o644, agent_unit(cfg))];
        if cfg.mcp.is_some() {
            f.push(ManagedFile::new(MCP_UNIT, 0o644, mcp_unit(cfg)));
        }
        f
    }

    fn packages(&self, _cfg: &Config) -> Vec<&'static str> {
        // conntrack reads flows over netlink (newer kernels have no procfs view).
        vec!["conntrack"]
    }

    fn validate_steps(&self, _cfg: &Config) -> Vec<Step> {
        vec![Step::cmd(&[
            "/usr/local/bin/rp-agent",
            "--config",
            "/etc/rp/rp.toml",
            "snapshot",
            "health",
        ])]
    }

    fn post_apply(&self, cfg: &Config) -> Vec<Step> {
        let a = cfg.agent.clone().unwrap_or_default();
        let token = a.token_file.clone();
        let mut steps = vec![
            // A random agent token, generated once on the device, root-only.
            Step {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    format!(
                        "umask 077 && [ -s '{token}' ] || od -An -tx1 -N32 /dev/urandom | tr -d ' \\n' > '{token}'"
                    ),
                ],
                best_effort: false,
            },
            Step::cmd(&["install", "-d", "-m", "0700", &a.state_dir]),
            Step::cmd(&["systemctl", "daemon-reload"]),
            Step::cmd(&["systemctl", "enable", "rp-agent.service"]),
            Step::cmd(&["systemctl", "restart", "rp-agent.service"]),
            Step::cmd(&["systemctl", "is-active", "--quiet", "rp-agent.service"]),
        ];
        if let Some(m) = &cfg.mcp {
            steps.push(Step {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    format!("umask 077 && [ -e '{0}' ] || : > '{0}'", m.clients_file),
                ],
                best_effort: false,
            });
            steps.push(Step::cmd(&["systemctl", "enable", "rp-mcp.service"]));
            steps.push(Step::cmd(&["systemctl", "restart", "rp-mcp.service"]));
        }
        steps
    }

    fn pre_rollback(&self) -> Vec<Step> {
        vec![Step::best_effort(&[
            "systemctl",
            "disable",
            "--now",
            "rp-mcp.service",
            "rp-agent.service",
        ])]
    }

    fn post_rollback(&self) -> Vec<Step> {
        vec![Step::cmd(&["systemctl", "daemon-reload"])]
    }

    fn requires(&self) -> &'static [&'static str] {
        &["base"]
    }

    fn next_steps(&self, cfg: &Config) -> Vec<String> {
        let mut n = vec!["Check: sudo rp-agent snapshot health".into()];
        if let Some(m) = &cfg.mcp {
            n.push("Create an MCP client: sudo rpctl mcp add-client <name> --cap read".into());
            n.push(format!(
                "MCP endpoint: http://{}/mcp  (or: ssh <device> rp-mcp --stdio)",
                m.listen
            ));
            n.push("Privileged requests appear in: sudo rpctl actions   approve with: sudo rpctl approve <id>".into());
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    fn cfg(mcp: bool) -> Config {
        let mut t =
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n[agent]\n".to_string();
        if mcp {
            t.push_str("[mcp]\n");
        }
        parse(&t).unwrap()
    }

    #[test]
    fn units_are_sandboxed_and_mcp_gets_credentials() {
        let f = Agent.render(&cfg(true));
        assert_eq!(f.len(), 2);
        let agent = &f[0].content;
        assert!(agent.contains("CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN"));
        assert!(
            agent.contains("ProtectSystem=strict")
                && agent.contains("ReadWritePaths=/var/lib/rp/agent")
        );
        let mcp = &f[1].content;
        assert!(mcp.contains("DynamicUser=yes") && mcp.contains("CapabilityBoundingSet=\n"));
        assert!(mcp.contains("LoadCredential=agent-token:/etc/rp/agent.token"));
        assert!(
            !mcp.contains("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"),
            "no local sockets for mcp"
        );
        assert_eq!(Agent.render(&cfg(false)).len(), 1);
    }

    #[test]
    fn token_is_generated_on_device_once() {
        let steps: Vec<String> = Agent.post_apply(&cfg(true)).iter().map(|s| s.display()).collect();
        assert!(steps[0].contains("[ -s '/etc/rp/agent.token' ] ||"));
        assert!(steps.iter().any(|s| s.contains("restart rp-mcp.service")));
    }
}
