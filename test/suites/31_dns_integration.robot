*** Settings ***
Documentation     rp-dns as a real process on loopback with fake upstream resolvers:
...               blocking, allow precedence, forwarding over UDP and TCP, failover,
...               SERVFAIL, suspicious-name logging to SQLite, hot reload, and abuse
...               resistance (malformed packets, rate limiting).
Resource          ../resources/dns.resource
Suite Setup       Start Everything
Suite Teardown    Terminate All Processes    kill=True
Test Tags         integration    dns

*** Variables ***
${TUNNEL}         4a6f686e20446f652073656e7420612073656372657420656e636f646564.t.example.org.

*** Test Cases ***
Ordinary Names Are Forwarded To The Upstream
    ${r}=    Lookup    www.example.
    Should Be Equal    ${r['rcode']}    NoError
    Should Be Equal    ${r['answers']}    ${{ ['203.0.113.99'] }}

Blocked Domains And Their Subdomains Get NXDOMAIN
    ${a}=    Lookup    ads.example.
    Should Be Equal    ${a['rcode']}    NXDomain
    ${b}=    Lookup    deep.tracker.ads.example.
    Should Be Equal    ${b['rcode']}    NXDomain

Names From A Blocklist File Are Blocked
    ${r}=    Lookup    malware.example.
    Should Be Equal    ${r['rcode']}    NXDomain

Allowlist Wins Over The Blocklist
    ${r}=    Lookup    cdn.ads.example.
    Should Be Equal    ${r['rcode']}    NoError

TCP Queries Work Too
    ${r}=    Lookup    www.example.    tcp=${True}
    Should Be Equal    ${r['answers']}    ${{ ['203.0.113.99'] }}
    ${b}=    Lookup    ads.example.    tcp=${True}
    Should Be Equal    ${b['rcode']}    NXDomain

Dead First Upstream Fails Over To The Next
    [Documentation]    The first configured upstream swallows queries; answers must still come.
    ${r}=    Lookup    failover.example.
    Should Be Equal    ${r['rcode']}    NoError
    Should Be True    ${r['ms']} < 1500
    # The dead upstream is now held down: later queries must not wait for it.
    ${again}=    Lookup    failover2.example.
    Should Be True    ${again['ms']} < 200    msg=dead upstream was not skipped (${again['ms']} ms)

Suspicious Tunnel-Like Name Is Forwarded But Logged
    ${r}=    Lookup    ${TUNNEL}
    Should Be Equal    ${r['rcode']}    NoError
    Wait Until Keyword Succeeds    5s    300ms    Event Logged    suspicious    ${TUNNEL.rstrip('.')}

Blocks Are Logged With The Matching List Entry
    Lookup    ads.example.
    Wait Until Keyword Succeeds    5s    300ms    Event Logged    blocked    ads.example
    ${out}=    Run Ok    %{RP_DNS=${REPO}/target/debug/rp-dns}    --config    ${DNS_DIR}/rp.toml
    ...    events    --action    blocked    --json
    ${rows}=    Evaluate    json.loads($out)    modules=json
    Should Contain    ${rows[0]['reason']}    blocklist:ads.example
    Should Be Equal    ${rows[0]['client']}    127.0.0.1

Malformed Packets Are Dropped And The Server Keeps Working
    [Tags]    integration    dns    security
    FOR    ${hex}    IN    00    ffff    0000010000010000000000    ${{ 'ab' * 600 }}
        Run Process    ${PROBE}    dns-raw    --server    127.0.0.1:${DNS_PORT}    --hex    ${hex}
    END
    ${r}=    Lookup    www.example.
    Should Be Equal    ${r['rcode']}    NoError

Hot Reload Picks Up New Blocklist Entries
    [Documentation]    SIGHUP reloads lists without dropping the listener.
    ${before}=    Lookup    newly-bad.example.
    Should Be Equal    ${before['rcode']}    NoError
    Append To File    ${DNS_DIR}/blocklist.txt    0.0.0.0 newly-bad.example\n
    Send Signal To Process    SIGHUP    rp-dns
    Wait Until Keyword Succeeds    5s    300ms    Is Blocked    newly-bad.example.

Flooding Client Gets REFUSED
    [Tags]    integration    dns    security
    [Documentation]    rate_limit_qps = 10 (burst 20): 100 back-to-back queries must be cut off.
    ${out}=    Run Ok    ${PROBE}    dns-bench    --server    127.0.0.1:${DNS_PORT}    --count    100
    ${j}=    Evaluate    json.loads($out)    modules=json
    Log    ${j}
    Should Be True    ${j['rcodes'].get('Refused', 0)} >= 50
    Should Be True    ${j['rcodes'].get('NoError', 0)} <= 40

All Upstreams Down Gives SERVFAIL Quickly
    [Documentation]    Separate instance whose only upstream is dead.
    Stop RP DNS
    ${dead}=    Start Fake Upstream    dead-only    silent=${True}
    Start RP DNS For Dead Upstream    ${dead}
    ${r}=    Lookup    www.example.
    Should Be Equal    ${r['rcode']}    ServFail
    Should Be True    ${r['ms']} < 2000

*** Keywords ***
Start Everything
    ${dead}=    Start Fake Upstream    dead    silent=${True}
    ${live}=    Start Fake Upstream    live
    ${dir}=    New Temp Dir
    Create File    ${dir}/list.txt    \# test list\n0.0.0.0 malware.example\n
    @{ups}=    Create List    ${dead}    ${live}
    ${extra}=    Catenate    SEPARATOR=\n
    ...    block = ["ads.example"]
    ...    allow = ["cdn.ads.example"]
    ...    rate_limit_qps = 10
    ...    blocklists = ["${dir}/list.txt", "DNSDIR/blocklist.txt"]
    Start RP DNS With Lists    ${ups}    ${extra}

Start RP DNS With Lists
    [Documentation]    The second blocklist lives in the instance dir so tests can append to it.
    [Arguments]    ${ups}    ${extra}
    ${dir}=    New Temp Dir
    Create File    ${dir}/blocklist.txt    \# appended by tests\n
    ${extra}=    Replace String    ${extra}    DNSDIR    ${dir}
    ${port}=    Free Port
    ${upl}=    Evaluate    ', '.join('"127.0.0.1:%s"' % p for p in $ups)
    ${toml}=    Catenate    SEPARATOR=\n
    ...    [device]
    ...    wan_if = "eth0"
    ...    lan_cidrs = ["192.0.2.0/24"]
    ...    [dns]
    ...    listen = ["127.0.0.1:${port}"]
    ...    upstreams = [${upl}]
    ...    upstream_timeout_ms = 400
    ...    events_db = "${dir}/events.sqlite"
    ...    ${extra}
    Create File    ${dir}/rp.toml    ${toml}\n
    Start Process    %{RP_DNS=${REPO}/target/debug/rp-dns}    --config    ${dir}/rp.toml    run
    ...    alias=rp-dns    stderr=${dir}/rp-dns.log
    Set Suite Variable    ${DNS_PORT}    ${port}
    Set Suite Variable    ${DNS_DIR}    ${dir}
    Wait Until Keyword Succeeds    5s    200ms    DNS Answers    www.example.

Start RP DNS For Dead Upstream
    [Arguments]    ${dead}
    @{ups}=    Create List    ${dead}
    Start RP DNS    ${ups}

Event Logged
    [Arguments]    ${action}    ${qname}
    ${out}=    Run Ok    %{RP_DNS=${REPO}/target/debug/rp-dns}    --config    ${DNS_DIR}/rp.toml
    ...    events    --action    ${action}    --json
    ${rows}=    Evaluate    json.loads($out)    modules=json
    ${names}=    Evaluate    [r['qname'] for r in $rows]
    Should Contain    ${names}    ${qname}

Is Blocked
    [Arguments]    ${name}
    ${r}=    Lookup    ${name}
    Should Be Equal    ${r['rcode']}    NXDomain
