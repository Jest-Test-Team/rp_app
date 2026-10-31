*** Settings ***
Documentation     rpctl dns module: golden rendering, LAN-only firewall rule, sandboxed unit,
...               validation order and dependency on base.
Resource          ../resources/rpctl.resource
Test Tags         cli    dns

*** Variables ***
${DNSCFG}         ${FIXTURES}/config/dns.toml

*** Test Cases ***
Rendered DNS Files Match Golden Copies
    ${out}=    New Temp Dir
    Run Ok    ${RPCTL}    --config    ${DNSCFG}    render    dns    --out    ${out}
    @{files}=    List Files Recursively    ${FIXTURES}/golden/dns
    Length Should Be    ${files}    3
    FOR    ${rel}    IN    @{files}
        ${want}=    Get File    ${FIXTURES}/golden/dns/${rel}
        ${got}=    Get File    ${out}/${rel}
        Should Be Equal    ${got}    ${want}    msg=${rel} differs from golden copy
    END

DNS Port Is Opened To The LAN Only
    ${out}=    Run Ok    ${RPCTL}    --config    ${DNSCFG}    render    dns
    Should Contain    ${out}    ip saddr @lan4 udp dport 53 accept
    Should Not Match Regexp    ${out}    (?m)^\\s+(udp|tcp) dport 53 accept

Service Runs Unprivileged In A Sandbox
    ${out}=    Run Ok    ${RPCTL}    --config    ${DNSCFG}    render    dns
    FOR    ${line}    IN    DynamicUser=yes    CapabilityBoundingSet=CAP_NET_BIND_SERVICE
    ...    ProtectSystem=strict    NoNewPrivileges=yes    SystemCallFilter=@system-service
        Should Contain    ${out}    ${line}
    END

DNS Requires Base
    ${root}=    Create Fake Root
    ${out}=    Rpctl    ${root}    1    apply    dns    config=${DNSCFG}
    Should Contain    ${out}    needs 'base' applied first

Apply Validates With rp-dns Before Starting It
    ${root}=    Create Fake Root
    Rpctl    ${root}    0    apply    base    config=${DNSCFG}
    Remove File    ${root}/cmds.log
    ${out}=    Rpctl    ${root}    0    apply    dns    config=${DNSCFG}
    Should Contain    ${out}    SECONDARY DNS
    ${check}=    Index Of Command    ${root}    /usr/local/bin/rp-dns --config /etc/rp/rp.toml check
    ${start}=    Index Of Command    ${root}    systemctl restart rp-dns.service
    ${alive}=    Index Of Command    ${root}    systemctl is-active --quiet rp-dns.service
    Should Be True    ${check} < ${start} < ${alive}

Failed Service Start Rolls Back
    ${root}=    Create Fake Root
    Rpctl    ${root}    0    apply    base    config=${DNSCFG}
    ${out}=    Rpctl    ${root}    1    apply    dns    config=${DNSCFG}    fail=systemctl is-active
    Should Contain    ${out}    changes were rolled back
    File Should Not Exist    ${root}/etc/systemd/system/rp-dns.service
    File Should Not Exist    ${root}/etc/rp/nft.d/40-dns.nft

Forwarding Loop Is Rejected
    ${tmp}=    New Temp Dir
    ${cfg}=    Get File    ${FIXTURES}/config/basic.toml
    Create File    ${tmp}/rp.toml    ${cfg}\n[dns]\nupstreams = ["127.0.0.1:53"]\n
    ${r}=    Run Expecting    3    ${RPCTL}    --config    ${tmp}/rp.toml    check
    Should Contain    ${r.stdout}    points back at rp-dns itself
