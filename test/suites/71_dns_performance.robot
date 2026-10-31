*** Settings ***
Documentation     DNS latency (informational, no root): rp-dns on loopback with a fake
...               upstream. Records p50/p95/p99 to results/perf.json. Fails only on errors.
...               Reference on a Pi 2B against public resolvers: +0.6 ms p50 over direct
...               queries, 0.57 ms p95 for locally blocked names, 4.8 MB RSS.
Resource          ../resources/dns.resource
Suite Setup       Start Bench Server
Suite Teardown    Terminate All Processes    kill=True
Test Tags         perf    dns

*** Variables ***
${RESULTS}        ${CURDIR}/../results

*** Test Cases ***
Latency Of Locally Blocked Names
    Bench    blocked    ads.example.

Latency Of Forwarded Names
    Bench    forwarded    www.example.

*** Keywords ***
Start Bench Server
    ${up}=    Start Fake Upstream    bench-up
    @{ups}=    Create List    ${up}
    Start RP DNS    ${ups}    block = ["ads.example"]\nrate_limit_qps = 100000

Bench
    [Arguments]    ${label}    ${name}
    ${out}=    Run Ok    ${PROBE}    dns-bench    --server    127.0.0.1:${DNS_PORT}    --name    ${name}
    ...    --count    500
    ${j}=    Evaluate    json.loads($out)    modules=json
    Should Be Equal As Integers    ${j['failures']}    0
    Log    dns-${label}: p50 ${j['p50_ms']} ms, p95 ${j['p95_ms']} ms    console=True
    Create Directory    ${RESULTS}
    ${line}=    Evaluate    json.dumps(dict(label='dns-' + $label, **$j))    modules=json
    Append To File    ${RESULTS}/perf.json    ${line}\n
