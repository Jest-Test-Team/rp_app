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

*** Keywords ***
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
        ...    subnet = "198.51.100.0/24"
    END
    Create File    ${dir}/rp.toml    ${toml}\n
    Run Ok    ${RPCTL}    --config    ${dir}/rp.toml    render    base    --out    ${dir}
    IF    '${module}' != 'base'
        Run Ok    ${RPCTL}    --config    ${dir}/rp.toml    render    ${module}    --out    ${dir}
    END
    RETURN    ${dir}
