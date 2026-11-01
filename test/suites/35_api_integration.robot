*** Settings ***
Documentation     The console API behind the real firewall in a network-namespace topology:
...               rp-api (fake device, real TLS) on the Pi's address, reachable from the LAN,
...               refused from the internet and from VPN clients.
Resource          ../resources/netns.resource
Resource          ../resources/rpctl.resource
Resource          ../resources/api.resource
Suite Setup       Create Topology
Suite Teardown    Destroy Topology
Test Tags         integration    requires-root    api

*** Test Cases ***
API Port Is Reachable From Everywhere Without A Firewall (Control)
    Start API In Rp Namespace
    In NS    rp    nft    flush    ruleset
    ${lan}=    TCP Connects From    lan    192.0.2.10    8443
    ${inet}=    TCP Connects From    inet    192.0.2.10    8443
    ${cli}=    TCP Connects From    cli    198.51.100.1    8443
    Should Be Equal    ${lan}${inet}${cli}    openopenopen

With The API Module Only The LAN Reaches It
    ${dir}=    New Temp Dir
    Create File    ${dir}/rp.toml    [device]\nwan_if = "eth0"\nlan_cidrs = ["192.0.2.0/24"]\n[api]\nallow_tailnet = false\n
    Run Ok    ${RPCTL}    --config    ${dir}/rp.toml    render    api    --out    ${dir}
    Load Firewall    ${dir}/etc/rp/.check/api.nft
    ${lan}=    TCP Connects From    lan    192.0.2.10    8443
    Should Be Equal    ${lan}    open
    ${inet}=    TCP Connects From    inet    192.0.2.10    8443
    Should Be Equal    ${inet}    closed    msg=the internet must never reach the API
    ${cli}=    TCP Connects From    cli    198.51.100.1    8443
    Should Be Equal    ${cli}    closed    msg=VPN clients are not management clients
    ${r}=    In NS    lan    ${PROBE}    https    --addr    192.0.2.10:8443    --path    /v1/info    --pin    ${PIN}
    ${j}=    Evaluate    json.loads($r.stdout)    modules=json
    Should Be Equal As Integers    ${j['status']}    200

A Console Firewall Rule Wins Over A Module Accept
    [Documentation]    The IoT AP lets the LAN open connections to IoT devices by default; a
    ...                firewall rule (05-firewall.nft, loaded first) dropping LAN → IoT 8080 wins.
    ${dir}=    New Temp Dir
    ${toml}=    Catenate    SEPARATOR=\n
    ...    [device]
    ...    wan_if = "eth0"
    ...    lan_cidrs = ["192.0.2.0/24"]
    ...    [ap]
    ...    ssid = "rp-netns-test"
    ...    country = "TW"
    ...    subnet = "198.51.100.128/25"
    ...    [firewall]
    ...    [[firewall.rules]]
    ...    name = "No LAN to IoT web"
    ...    from = "lan"
    ...    to = "iot"
    ...    proto = "tcp"
    ...    ports = [8080]
    ...    action = "drop"
    Create File    ${dir}/rp.toml    ${toml}\n
    Run Ok    ${RPCTL}    --config    ${dir}/rp.toml    render    ap    --out    ${dir}
    Run Ok    ${RPCTL}    --config    ${dir}/rp.toml    render    firewall    --out    ${dir}
    # Base + firewall (first), then the AP snippet: the order /etc/rp/nft.d gives them.
    ${fw}=    Get File    ${dir}/etc/rp/.check/firewall.nft
    ${ap}=    Get File    ${dir}/etc/rp/nft.d/60-ap.nft
    Create File    ${dir}/etc/rp/all.nft    ${fw}\n${ap}
    Load Firewall    ${dir}/etc/rp/all.nft
    ${blocked}=    HTTP From    lan    198.51.100.130:8080
    Should Be Equal    ${blocked}    0    msg=the console rule must win over the AP's LAN → IoT accept
    # Control: without the rule the AP's accept lets the LAN in.
    ${ctl}=    Get File    ${dir}/etc/rp/.check/ap.nft
    Create File    ${dir}/etc/rp/ctl.nft    ${ctl}
    Load Firewall    ${dir}/etc/rp/ctl.nft
    ${open}=    HTTP From    lan    198.51.100.130:8080
    Should Be Equal    ${open}    200

Every Firewall Rule Shape Loads Into nftables
    ${dir}=    New Temp Dir
    ${toml}=    Catenate    SEPARATOR=\n
    ...    [device]
    ...    wan_if = "eth0"
    ...    lan_cidrs = ["192.0.2.0/24", "2001:db8:1::/64"]
    ...    [ap]
    ...    ssid = "rp-netns-test"
    ...    country = "TW"
    ...    subnet = "198.51.100.128/25"
    ...    [vpn]
    ...    mode = "wireguard"
    ...    [firewall]
    ...    [[firewall.rules]]
    ...    name = "log and reject"
    ...    from = "iot"
    ...    to = "wan"
    ...    proto = "tcp"
    ...    ports = [23, 2323]
    ...    action = "reject"
    ...    log = true
    ...    [[firewall.rules]]
    ...    name = "udp reject"
    ...    from = "iot"
    ...    to = "wan"
    ...    proto = "udp"
    ...    ports = [1900]
    ...    action = "reject"
    ...    [[firewall.rules]]
    ...    name = "icmp both families"
    ...    from = "wan"
    ...    to = "iot"
    ...    proto = "icmp"
    ...    action = "drop"
    ...    [[firewall.rules]]
    ...    name = "v6 dest"
    ...    from = "vpn"
    ...    to = "lan"
    ...    dest = ["2001:db8:1::40/128", "192.0.2.40/32"]
    ...    action = "accept"
    ...    [[firewall.rules]]
    ...    name = "device input"
    ...    from = "iot"
    ...    to = "device"
    ...    proto = "udp"
    ...    ports = [161, 162]
    ...    action = "drop"
    ...    log = true
    Create File    ${dir}/rp.toml    ${toml}\n
    Run Ok    ${RPCTL}    --config    ${dir}/rp.toml    render    firewall    --out    ${dir}
    Load Firewall    ${dir}/etc/rp/.check/firewall.nft
    ${r}=    In NS    rp    nft    list    chain    inet    rp    mod_forward
    Should Contain    ${r.stdout}    log prefix "rp-fw-logandreject "
    Should Contain    ${r.stdout}    reject with tcp reset
    Should Contain    ${r.stdout}    2001:db8:1::40

*** Keywords ***
Start API In Rp Namespace
    ${root}=    New Temp Dir
    Start Process    ip    netns    exec    ${NS}rp    ${RPAPI}    --fake    --fake-root    ${root}/dev
    ...    --listen    0.0.0.0:8443    --ready-file    ${root}/ready.json    alias=ns-api
    Wait Until Created    ${root}/ready.json    timeout=20s
    ${ready}=    Evaluate    json.load(open($root + '/ready.json'))    modules=json
    Set Suite Variable    ${PIN}    ${ready['cert_sha256']}
