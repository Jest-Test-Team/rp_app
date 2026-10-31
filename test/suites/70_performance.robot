*** Settings ***
Documentation     Performance (informational): forwarding throughput through the Pi's
...               network namespace with and without the rendered VPN ruleset (filter + NAT),
...               measured with rp-probe. Results are written to results/perf.json.
...               Tests only fail if traffic does not flow at all.
...               This measures nftables/forwarding cost on the CPU, not WireGuard crypto.
Resource          ../resources/netns.resource
Resource          ../resources/rpctl.resource
Suite Setup       Create Topology
Suite Teardown    Destroy Topology
Test Tags         perf    requires-root

*** Variables ***
${SECONDS}        8
${RESULTS}        ${CURDIR}/../results

*** Test Cases ***
Forwarding Throughput Without Rules
    Clear Firewall
    ${mbps}=    Measure Throughput    no-rules
    Should Be True    ${mbps} > 0

Forwarding Throughput With VPN Rules And NAT
    ${dir}=    New Temp Dir
    ${toml}=    Catenate    SEPARATOR=\n
    ...    [device]
    ...    wan_if = "eth0"
    ...    lan_cidrs = ["192.0.2.0/24"]
    ...    [vpn]
    ...    mode = "wireguard"
    ...    [vpn.wireguard]
    ...    subnet = "198.51.100.0/24"
    Create File    ${dir}/rp.toml    ${toml}\n
    Run Ok    ${RPCTL}    --config    ${dir}/rp.toml    render    vpn    --out    ${dir}
    Load Firewall    ${dir}/etc/rp/.check/vpn.nft
    ${mbps}=    Measure Throughput    vpn-rules-nat
    Should Be True    ${mbps} > 0

*** Keywords ***
Measure Throughput
    [Arguments]    ${label}
    ${port}=    Evaluate    __import__('random').randint(20000, 40000)
    Start Process    ip    netns    exec    ${NS}inet    ${PROBE}    tput-server
    ...    --bind    203.0.113.10:${port}    alias=tput-${label}
    Sleep    0.5s
    ${client}=    In NS    cli    ${PROBE}    tput-client    --connect    203.0.113.10:${port}
    ...    --seconds    ${SECONDS}    timeout=60s
    Should Be Equal As Integers    ${client.rc}    0    msg=${client.stdout}
    ${server}=    Wait For Process    tput-${label}    timeout=30s
    ${result}=    Evaluate    json.loads($server.stdout)    modules=json
    ${mbps}=    Set Variable    ${result['mbps']}
    Log    ${label}: ${mbps} Mbit/s    console=True
    Create Directory    ${RESULTS}
    ${line}=    Evaluate    json.dumps(dict(label=$label, **$result))    modules=json
    Append To File    ${RESULTS}/perf.json    ${line}\n
    RETURN    ${mbps}
