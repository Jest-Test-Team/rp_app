*** Settings ***
Documentation     rpctl vpn module: rendering for both modes, dependency on base, safe apply
...               ordering, rollback, and WireGuard peer creation.
Resource          ../resources/rpctl.resource
Test Tags         cli    vpn

*** Variables ***
${WG}             ${FIXTURES}/config/wireguard.toml
${TS}             ${FIXTURES}/config/tailscale.toml
# A throwaway server key used only by these tests (not a secret).
${SERVER_KEY}     yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=

*** Test Cases ***
Rendered VPN Files Match Golden Copies
    [Template]    Module Matches Golden
    ${WG}    wireguard
    ${TS}    tailscale

VPN Snippet Blocks The LAN Before Accepting Internet Traffic
    ${out}=    Run Ok    ${RPCTL}    --config    ${WG}    render    vpn
    Should Contain    ${out}    iifname "wg0" ip daddr @vpn_block4 drop
    Should Contain    ${out}    192.0.2.0/24
    ${drop}=    Evaluate    $out.index('ip daddr @vpn_block4 drop')
    ${accept}=    Evaluate    $out.index('iifname "wg0" oifname "eth0" accept')
    Should Be True    ${drop} < ${accept}

WireGuard Config Never Contains A Private Key
    ${out}=    Run Ok    ${RPCTL}    --config    ${WG}    render    vpn
    Should Not Contain    ${out}    PrivateKey
    Should Contain    ${out}    PostUp = wg set %i private-key /etc/rp/wireguard/private.key

Rendering VPN Without A Section Is An Error
    ${r}=    Run Expecting    1    ${RPCTL}    --config    ${FIXTURES}/config/basic.toml    apply    vpn
    ...    --dry-run    --root    /nonexistent
    Should Contain    ${r.stdout}    no [vpn] section

VPN Requires Base To Be Applied First
    ${root}=    Create Fake Root
    ${out}=    Rpctl    ${root}    1    apply    vpn    config=${WG}
    Should Contain    ${out}    needs 'base' applied first

VPN Apply Validates The Combined Ruleset And Arms The Timer
    ${root}=    Create Fake Root
    Rpctl    ${root}    0    apply    base    config=${WG}
    Remove File    ${root}/cmds.log
    ${out}=    Rpctl    ${root}    0    apply    vpn    config=${WG}
    Should Contain    ${out}    next: Forward UDP 51820
    File Should Exist    ${root}/etc/rp/nft.d/50-vpn.nft
    File Should Not Exist    ${root}/etc/rp/.check/vpn.nft
    ${check}=    Index Of Command    ${root}    nft -c -f
    ${reload}=    Index Of Command    ${root}    systemctl reload-or-restart rp-firewall.service
    ${wg}=    Index Of Command    ${root}    systemctl restart wg-quick@wg0.service
    Should Be True    ${check} < ${reload} < ${wg}
    @{cmds}=    Recorded Commands    ${root}
    Should Contain Match    ${cmds}    nft -c -f */staging/vpn/etc/rp/.check/vpn.nft

VPN Rollback Turns Forwarding Off And Stops The Tunnel
    ${root}=    Create Fake Root
    Rpctl    ${root}    0    apply    base    config=${WG}
    Rpctl    ${root}    0    apply    vpn    config=${WG}
    Remove File    ${root}/cmds.log
    ${out}=    Rpctl    ${root}    0    rollback    vpn    config=${WG}
    Should Contain    ${out}    rolled back
    File Should Not Exist    ${root}/etc/rp/nft.d/50-vpn.nft
    File Should Not Exist    ${root}/etc/wireguard/wg0.conf
    Index Of Command    ${root}    sysctl -w net.ipv4.ip_forward=0
    Index Of Command    ${root}    sh -c systemctl disable --now 'wg-quick@*.service'

Tailscale Adds Its Repository Before Installing And Uses The Key File
    ${root}=    Create Fake Root
    Rpctl    ${root}    0    apply    base    config=${TS}
    Remove File    ${root}/cmds.log
    # dpkg-query reports nothing installed here, so packages are installed.
    ${r}=    Run Expecting    0    ${RPCTL}    --config    ${TS}    --root    ${root}
    ...    --record-commands    ${root}/cmds.log    --fake-output    id -u\=0    apply    vpn
    ${key}=    Index Of Command    ${root}    curl -fsSL --proto =https
    ${update}=    Index Of Command    ${root}    env DEBIAN_FRONTEND=noninteractive apt-get update
    ${install}=    Index Of Command    ${root}    env DEBIAN_FRONTEND=noninteractive apt-get install
    Should Be True    ${key} < ${update} < ${install}
    Index Of Command    ${root}    tailscale up --auth-key=file:/etc/rp/tailscale.key --hostname=rp-exit
    File Should Exist    ${root}/etc/apt/sources.list.d/tailscale.list

Add Peer Prints A Client Config Once And Valid TOML
    ${root}=    Create Fake Root
    Create File    ${root}/etc/rp/wireguard/private.key    ${SERVER_KEY}\n
    ${out}=    Run Ok    ${RPCTL}    --config    ${WG}    --root    ${root}    vpn    add-peer    laptop
    ...    --no-qr
    Should Contain    ${out}    shown ONCE
    Should Contain    ${out}    Address = 198.51.100.3/32
    Should Contain    ${out}    AllowedIPs = 0.0.0.0/0, ::/0
    Should Contain    ${out}    Endpoint = vpn.example.org:51820
    Should Match Regexp    ${out}    PrivateKey = [A-Za-z0-9+/]{43}=
    Should Contain    ${out}    name = "laptop"
    Should Contain    ${out}    host = 3
    # The generated peer TOML appended to the config must validate.
    ${toml}=    Evaluate    $out.split('then run: sudo rpctl apply vpn ----\\n', 1)[1]
    ${cfg}=    Get File    ${WG}
    ${tmp}=    New Temp Dir
    Create File    ${tmp}/rp.toml    ${cfg}\n${toml}
    Run Ok    ${RPCTL}    --config    ${tmp}/rp.toml    check

Add Peer Prints A QR Code By Default
    ${root}=    Create Fake Root
    Create File    ${root}/etc/rp/wireguard/private.key    ${SERVER_KEY}\n
    ${out}=    Run Ok    ${RPCTL}    --config    ${WG}    --root    ${root}    vpn    add-peer    tablet
    Should Contain Any    ${out}    █    ▀    ▄

Add Peer Refuses Duplicates And Needs The Server Key
    ${root}=    Create Fake Root
    ${r}=    Run Expecting    1    ${RPCTL}    --config    ${WG}    --root    ${root}    vpn    add-peer    laptop
    Should Contain    ${r.stdout}    apply vpn` first
    Create File    ${root}/etc/rp/wireguard/private.key    ${SERVER_KEY}\n
    ${d}=    Run Expecting    1    ${RPCTL}    --config    ${WG}    --root    ${root}    vpn    add-peer    phone
    Should Contain    ${d.stdout}    already exists
    ${bad}=    Run Expecting    1    ${RPCTL}    --config    ${WG}    --root    ${root}    vpn    add-peer
    ...    bad;name
    Should Contain    ${bad.stdout}    must be letters

*** Keywords ***
Module Matches Golden
    [Arguments]    ${config}    ${golden}
    ${out}=    New Temp Dir
    Run Ok    ${RPCTL}    --config    ${config}    render    vpn    --out    ${out}
    @{files}=    List Files Recursively    ${FIXTURES}/golden/${golden}
    Should Not Be Empty    ${files}
    FOR    ${rel}    IN    @{files}
        ${want}=    Get File    ${FIXTURES}/golden/${golden}/${rel}
        ${got}=    Get File    ${out}/${rel}
        Should Be Equal    ${got}    ${want}    msg=${rel} differs from golden copy
    END
