*** Settings ***
Documentation     Start rp-dns against fake upstreams on loopback (no root needed).
Resource          common.resource

*** Variables ***
${DNS_PORT}       ${EMPTY}
${DNS_DIR}        ${EMPTY}

*** Keywords ***
Free Port
    ${p}=    Evaluate
    ...    (lambda s: (s.bind(('127.0.0.1', 0)), s.getsockname()[1], s.close())[1])(__import__('socket').socket(__import__('socket').AF_INET, __import__('socket').SOCK_DGRAM))
    RETURN    ${p}

Start Fake Upstream
    [Arguments]    ${alias}    ${silent}=${False}
    ${port}=    Free Port
    @{extra}=    Create List
    IF    ${silent}    Append To List    ${extra}    --silent
    Start Process    ${PROBE}    dns-fake-upstream    --bind    127.0.0.1:${port}    @{extra}
    ...    alias=${alias}
    RETURN    ${port}

Start RP DNS
    [Documentation]    Write a config with the given upstream ports and extra TOML, start rp-dns.
    [Arguments]    ${upstreams}    ${extra}=${EMPTY}
    ${dir}=    New Temp Dir
    ${port}=    Free Port
    ${ups}=    Evaluate    ', '.join('"127.0.0.1:%s"' % p for p in $upstreams)
    ${toml}=    Catenate    SEPARATOR=\n
    ...    [device]
    ...    wan_if = "eth0"
    ...    lan_cidrs = ["192.0.2.0/24"]
    ...    [dns]
    ...    listen = ["127.0.0.1:${port}"]
    ...    upstreams = [${ups}]
    ...    upstream_timeout_ms = 400
    ...    events_db = "${dir}/events.sqlite"
    ...    ${extra}
    Create File    ${dir}/rp.toml    ${toml}\n
    Start Process    %{RP_DNS=${REPO}/target/debug/rp-dns}    --config    ${dir}/rp.toml    run
    ...    alias=rp-dns    stderr=${dir}/rp-dns.log
    Set Suite Variable    ${DNS_PORT}    ${port}
    Set Suite Variable    ${DNS_DIR}    ${dir}
    Wait Until Keyword Succeeds    5s    200ms    DNS Answers    www.example.

DNS Answers
    [Arguments]    ${name}
    ${r}=    Lookup    ${name}
    Should Not Be Equal    ${r['rcode']}    Timeout

Lookup
    [Arguments]    ${name}    ${type}=A    ${tcp}=${False}
    @{flags}=    Create List
    IF    ${tcp}    Append To List    ${flags}    --tcp
    ${r}=    Run Process    ${PROBE}    dns-query    --server    127.0.0.1:${DNS_PORT}    --name    ${name}
    ...    --type    ${type}    --timeout-ms    2000    @{flags}
    ${j}=    Evaluate    json.loads($r.stdout)    modules=json
    RETURN    ${j}

Stop RP DNS
    Run Keyword And Ignore Error    Terminate Process    rp-dns
