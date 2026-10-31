*** Settings ***
Documentation     Integration: real rendered nftables rules loaded into an isolated network
...               namespace topology. Proves the base firewall's default deny and SSH scoping,
...               and that VPN clients reach the internet (masqueraded) but never the home LAN.
Resource          ../resources/netns.resource
Resource          ../resources/rpctl.resource
Suite Setup       Create Topology
Suite Teardown    Destroy Topology
Test Setup        Clear Firewall
Test Tags         integration    requires-root

*** Variables ***
${CFG_DIR}        ${EMPTY}

*** Test Cases ***
Without A Firewall Everything Is Reachable (Control)
    [Documentation]    Proves the isolation tests below are meaningful: with no rules the
    ...                VPN client CAN reach the LAN, the router and the Pi.
    ${s}=    HTTP From    cli    203.0.113.10:8080
    Should Be Equal    ${s}    200
    ${l}=    HTTP From    cli    192.0.2.50:8080
    Should Be Equal    ${l}    200    msg=topology sanity check: LAN reachable without rules
    ${ssh}=    TCP Connects From    cli    192.0.2.10    22
    Should Be Equal    ${ssh}    open

Base Firewall Blocks All Forwarding By Default
    ${dir}=    Render    base    vpn=${EMPTY}
    Load Firewall    ${dir}/etc/rp/nftables.nft
    ${s}=    HTTP From    cli    203.0.113.10:8080
    Should Be Equal    ${s}    0

Base Firewall Allows SSH From The LAN Only
    ${dir}=    Render    base    vpn=${EMPTY}
    Load Firewall    ${dir}/etc/rp/nftables.nft
    ${lan}=    TCP Connects From    lan    192.0.2.10    22
    Should Be Equal    ${lan}    open
    ${cli}=    TCP Connects From    cli    198.51.100.1    22
    Should Be Equal    ${cli}    closed
    ${other}=    TCP Connects From    lan    192.0.2.10    8081
    Should Be Equal    ${other}    closed

VPN Client Reaches The Internet Through The Exit Node
    ${dir}=    Render    vpn    vpn=wireguard
    Load Firewall    ${dir}/etc/rp/.check/vpn.nft
    ${s}=    HTTP From    cli    203.0.113.10:8080
    Should Be Equal    ${s}    200

VPN Traffic Is Masqueraded Behind The Pi
    ${dir}=    Render    vpn    vpn=wireguard
    Load Firewall    ${dir}/etc/rp/.check/vpn.nft
    ${before}=    Get File Size    ${TEMPDIR}/${NS}inet-http.log
    ${s}=    HTTP From    cli    203.0.113.10:8080
    Should Be Equal    ${s}    200
    ${log}=    Get File    ${TEMPDIR}/${NS}inet-http.log
    # Only the lines written by this request (earlier tests share the server).
    ${new}=    Evaluate    $log.encode()[int($before):].decode()
    Should Contain    ${new}    192.0.2.10
    Should Not Contain    ${new}    198.51.100.2

VPN Client Cannot Reach The Home LAN Router Or The Pi's SSH
    ${dir}=    Render    vpn    vpn=wireguard
    Load Firewall    ${dir}/etc/rp/.check/vpn.nft
    ${lan}=    HTTP From    cli    192.0.2.50:8080
    Should Be Equal    ${lan}    0
    ${router}=    TCP Connects From    cli    192.0.2.1    80
    Should Be Equal    ${router}    closed
    ${ssh}=    TCP Connects From    cli    192.0.2.10    22
    Should Be Equal    ${ssh}    closed

Explicit allow_lan Exception Opens Exactly One Host
    ${dir}=    Render    vpn    vpn=wireguard    allow_lan=["192.0.2.50/32"]
    Load Firewall    ${dir}/etc/rp/.check/vpn.nft
    ${lan}=    HTTP From    cli    192.0.2.50:8080
    Should Be Equal    ${lan}    200
    ${router}=    TCP Connects From    cli    192.0.2.1    80
    Should Be Equal    ${router}    closed

Removing The VPN Snippet Restores Default Deny
    ${dir}=    Render    vpn    vpn=wireguard
    Load Firewall    ${dir}/etc/rp/.check/vpn.nft
    ${s}=    HTTP From    cli    203.0.113.10:8080
    Should Be Equal    ${s}    200
    Load Firewall    ${dir}/etc/rp/nftables.nft
    ${after}=    HTTP From    cli    203.0.113.10:8080
    Should Be Equal    ${after}    0

IoT Client Reaches The Internet Masqueraded Behind The Pi
    [Tags]    integration    requires-root    ap
    ${dir}=    Render AP
    Load Firewall    ${dir}/etc/rp/.check/ap.nft
    ${before}=    Get File Size    ${TEMPDIR}/${NS}inet-http.log
    ${s}=    HTTP From    iot    203.0.113.10:8080
    Should Be Equal    ${s}    200
    ${log}=    Get File    ${TEMPDIR}/${NS}inet-http.log
    ${new}=    Evaluate    $log.encode()[int($before):].decode()
    Should Contain    ${new}    192.0.2.10

IoT Client Cannot Reach The LAN Router Or The Pi
    [Tags]    integration    requires-root    ap
    ${dir}=    Render AP
    Load Firewall    ${dir}/etc/rp/.check/ap.nft
    ${lan}=    HTTP From    iot    192.0.2.50:8080
    Should Be Equal    ${lan}    0
    ${router}=    TCP Connects From    iot    192.0.2.1    80
    Should Be Equal    ${router}    closed
    ${ssh}=    TCP Connects From    iot    198.51.100.129    22
    Should Be Equal    ${ssh}    closed
    ${ssh2}=    TCP Connects From    iot    192.0.2.10    22
    Should Be Equal    ${ssh2}    closed

IoT Client Cannot Reach VPN Clients
    [Tags]    integration    requires-root    ap
    ${dir}=    Render AP
    Load Firewall    ${dir}/etc/rp/.check/ap.nft
    ${r}=    TCP Connects From    iot    198.51.100.2    22
    Should Be Equal    ${r}    closed

LAN Can Manage IoT Devices Unless Disabled
    [Tags]    integration    requires-root    ap
    ${dir}=    Render AP
    Load Firewall    ${dir}/etc/rp/.check/ap.nft
    ${ok}=    HTTP From    lan    198.51.100.130:8080
    Should Be Equal    ${ok}    200
    ${off}=    Render AP    extra=lan_can_reach_clients = false
    Load Firewall    ${off}/etc/rp/.check/ap.nft
    ${blocked}=    HTTP From    lan    198.51.100.130:8080
    Should Be Equal    ${blocked}    0

IoT Gets DNS From The Pi Only When The DNS Module Is Configured
    [Tags]    integration    requires-root    ap    dns
    ${plain}=    Render AP
    Load Firewall    ${plain}/etc/rp/.check/ap.nft
    ${closed}=    TCP Connects From    iot    198.51.100.129    53
    Should Be Equal    ${closed}    closed
    ${with_dns}=    Render AP    dns=${True}
    Load Firewall    ${with_dns}/etc/rp/.check/ap.nft
    ${open}=    TCP Connects From    iot    198.51.100.129    53
    Should Be Equal    ${open}    open

Approved Quarantine By IP Cuts The Client Off And Expires
    [Tags]    integration    requires-root    ap    mcp
    [Documentation]    The exact element command `rpctl approve` runs, applied in the Pi namespace.
    ${dir}=    Render AP
    Load Firewall    ${dir}/etc/rp/.check/ap.nft
    ${ok}=    HTTP From    iot    203.0.113.10:8080
    Should Be Equal    ${ok}    200
    ${r}=    In NS    rp    nft    add    element    inet    rp    ap_quarantine4    { 198.51.100.130 timeout 15s }
    Should Be Equal As Integers    ${r.rc}    0    msg=${r.stdout}
    ${t0}=    Evaluate    time.monotonic()    modules=time
    ${blocked}=    HTTP From    iot    203.0.113.10:8080
    Should Be Equal    ${blocked}    0
    ${lan}=    HTTP From    lan    198.51.100.130:8080
    Should Be Equal    ${lan}    0    msg=traffic towards a quarantined client is dropped too
    ${left}=    Evaluate    max(0, 16 - (time.monotonic() - $t0))    modules=time
    Sleep    ${left}s
    ${back}=    HTTP From    iot    203.0.113.10:8080
    Should Be Equal    ${back}    200    msg=the quarantine must expire on its own

Quarantine Cuts A Connection That Was Already Established
    [Tags]    integration    requires-root    ap    mcp
    [Documentation]    Quarantine rules run before conntrack accepts established traffic.
    ${dir}=    Render AP
    Load Firewall    ${dir}/etc/rp/.check/ap.nft
    ${client}=    Catenate    SEPARATOR=\n
    ...    import socket, time
    ...    s = socket.create_connection(('203.0.113.10', 7777), timeout=3)
    ...    s.sendall(b'1'); print('first', s.recv(8) == b'1', flush=True)
    ...    time.sleep(3)
    ...    try:
    ...    \ \ s.sendall(b'2'); print('second', 'ok' if s.recv(8) == b'2' else 'closed')
    ...    except Exception:
    ...    \ \ print('second', 'blocked')
    Start Process    ip    netns    exec    ${NS}iot    python3    -c    ${client}    alias=longlived
    Sleep    1.5s
    In NS    rp    nft    add    element    inet    rp    ap_quarantine4    { 198.51.100.130 timeout 1m }
    ${r}=    Wait For Process    longlived    timeout=20s
    Should Contain    ${r.stdout}    first True
    Should Contain    ${r.stdout}    second blocked    msg=established connection survived: ${r.stdout}
    In NS    rp    nft    flush    set    inet    rp    ap_quarantine4

Approved Isolation By MAC Survives An IP Change
    [Tags]    integration    requires-root    ap    mcp
    ${dir}=    Render AP
    Load Firewall    ${dir}/etc/rp/.check/ap.nft
    ${mac}=    In NS    iot    cat    /sys/class/net/eth0/address
    ${r}=    In NS    rp    nft    add    element    inet    rp    ap_quarantine_mac    { ${mac.stdout.strip()} timeout 1m }
    Should Be Equal As Integers    ${r.rc}    0    msg=${r.stdout}
    ${blocked}=    HTTP From    iot    203.0.113.10:8080
    Should Be Equal    ${blocked}    0
    In NS    iot    ip    addr    add    198.51.100.131/25    dev    eth0
    ${code}=    Catenate    SEPARATOR=\n
    ...    import socket
    ...    s = socket.socket(); s.settimeout(3); s.bind(('198.51.100.131', 0))
    ...    print('open' if s.connect_ex(('203.0.113.10', 8080)) == 0 else 'closed')
    ${moved}=    In NS    iot    python3    -c    ${code}
    Should Be Equal    ${moved.stdout.strip()}    closed
    In NS    iot    ip    addr    del    198.51.100.131/25    dev    eth0

*** Keywords ***
Render AP
    [Arguments]    ${extra}=${EMPTY}    ${dns}=${False}
    ${dir}=    New Temp Dir
    ${toml}=    Catenate    SEPARATOR=\n
    ...    [device]
    ...    wan_if = "eth0"
    ...    lan_cidrs = ["192.0.2.0/24"]
    ...    [ap]
    ...    ssid = "rp-netns-test"
    ...    country = "TW"
    ...    subnet = "198.51.100.128/25"
    ...    ${extra}
    IF    ${dns}
        ${toml}=    Catenate    SEPARATOR=\n    ${toml}    [dns]    upstreams = ["203.0.113.10:53"]
    END
    Create File    ${dir}/rp.toml    ${toml}\n
    Run Ok    ${RPCTL}    --config    ${dir}/rp.toml    render    ap    --out    ${dir}
    RETURN    ${dir}

Render
    [Documentation]    Write a config for the topology and render ${module} (plus base) into a temp dir.
    [Arguments]    ${module}    ${vpn}=wireguard    ${allow_lan}=[]
    ${dir}=    New Temp Dir
    ${toml}=    Catenate    SEPARATOR=\n
    ...    [device]
    ...    wan_if = "eth0"
    ...    lan_cidrs = ["192.0.2.0/24"]
    IF    '${vpn}' != ''
        ${toml}=    Catenate    SEPARATOR=\n    ${toml}
        ...    [vpn]
        ...    mode = "${vpn}"
        ...    allow_lan = ${allow_lan}
        ...    [vpn.wireguard]
        ...    subnet = "198.51.100.0/25"
    END
    Create File    ${dir}/rp.toml    ${toml}\n
    Run Ok    ${RPCTL}    --config    ${dir}/rp.toml    render    base    --out    ${dir}
    IF    '${module}' != 'base'
        Run Ok    ${RPCTL}    --config    ${dir}/rp.toml    render    ${module}    --out    ${dir}
    END
    RETURN    ${dir}
