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

*** Keywords ***
Start API In Rp Namespace
    ${root}=    New Temp Dir
    Start Process    ip    netns    exec    ${NS}rp    ${RPAPI}    --fake    --fake-root    ${root}/dev
    ...    --listen    0.0.0.0:8443    --ready-file    ${root}/ready.json    alias=ns-api
    Wait Until Created    ${root}/ready.json    timeout=20s
    ${ready}=    Evaluate    json.load(open($root + '/ready.json'))    modules=json
    Set Suite Variable    ${PIN}    ${ready['cert_sha256']}
