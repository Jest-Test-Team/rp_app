*** Settings ***
Documentation     Security: what a manipulated model (prompt injection), a rogue local
...               client or a malicious network device could try — and must not achieve.
...               Maps to confirmations V1-5 (CIDR allow-list), V1-6 (injection), V1-7
...               (privileged control), V1-8 (rate limit), V1-9 (audit), plus transport.
Resource          ../resources/mcp.resource
Resource          ../resources/rpctl.resource
Suite Setup       Start Agent And MCP    rate=40
Suite Teardown    Stop Agent And MCP
Test Tags         security    mcp

*** Test Cases ***
Scan Targets Outside The Allow-List Are Refused
    [Template]    Scan Is Refused
    0.0.0.0/0              never an allowed target
    203.0.113.0/24         outside the allowed networks
    192.0.2.0/16           addresses; the limit is
    192.0.2.0/23           addresses; the limit is
    198.51.100.0/24        outside the allowed networks
    2001:db8::/64          IPv6 targets are not allowed
    10.0.0.0/8             addresses; the limit is
    127.0.0.0/8            addresses; the limit is
    not-a-network          not a CIDR network

Injection Strings In Arguments Never Reach A Shell
    [Template]    Operator Call Is Refused
    scan_network      {"target": "192.0.2.0/24; rm -rf /"}                    forbidden characters
    scan_network      {"target": "$(reboot)"}                                  forbidden characters
    scan_network      {"target": "192.0.2.0/24`id`"}                           forbidden characters
    block_device      {"ip": "198.51.100.140 && nft flush ruleset"}            forbidden characters
    block_device      {"ip": "198.51.100.140", "reason": "ok\\n$(curl evil)"}  forbidden characters
    isolate_client    {"mac": "02:aa:bb:cc:dd:02|sh"}                          forbidden characters
    query_dns_events  {"action": "blocked' OR 1=1 --"}                         must be one of

Unknown Or Malformed Arguments Are Refused
    [Template]    Operator Call Is Refused
    scan_network          {"target": "192.0.2.0/24", "ports": "1-65535"}    unknown argument
    block_device          {"ip": "198.51.100.140", "command": "x"}          unknown argument
    block_device          {}                                                missing required argument
    query_dns_events      {"limit": 100000}                                 between 1 and 1000
    get_flows             {"limit": "all"}                                  must be an integer
    get_system_health     {"verbose": true}                                 unknown argument

Privileged Targets Are Confined To Access-Point Clients
    [Template]    Operator Call Is Refused
    block_device      {"ip": "192.0.2.50"}                         outside
    block_device      {"ip": "192.0.2.10"}                         outside
    block_device      {"ip": "198.51.100.129"}                     refusing to block the gateway
    block_device      {"ip": "198.51.100.128"}                     not a host address
    block_device      {"ip": "198.51.100.140", "ttl_minutes": 0}   between 1 and 1440
    isolate_client    {"mac": "ff:ff:ff:ff:ff:ff"}                 multicast/broadcast
    isolate_client    {"mac": "01:00:5e:00:00:01"}                 multicast/broadcast

A Model Cannot Approve Its Own Request
    [Documentation]    No MCP method or tool approves; only `rpctl approve` on the device can.
    ${r}=    Call Tool    RP_TEST_OPERATOR    block_device    {"ip": "198.51.100.140"}
    ${id}=    Set Variable    ${r['structuredContent']['id']}
    FOR    ${attempt}    IN    approve    approve_action    rpctl_approve
        ${x}=    Call Tool    RP_TEST_OPERATOR    ${attempt}    {"id": "${id}"}
        Should Be Equal    ${x['isError']}    ${True}
        Should Contain    ${x['content'][0]['text']}    unknown tool
    END
    ${m}=    MCP    RP_TEST_OPERATOR    actions/approve    {"id": "${id}"}
    Should Be Equal As Integers    ${m['body']['error']['code']}    -32601
    ${p}=    Call Tool    RP_TEST_VIEWER    list_pending_actions
    ${states}=    Evaluate    {a['id']: a['status'] for a in $p['structuredContent']['actions']}
    Should Be Equal    ${states['${id}']}    pending

A Tampered Stored Request Is Re-Validated At Approval
    [Documentation]    The request file is data. Editing it to target the LAN must not work.
    ${r}=    Call Tool    RP_TEST_OPERATOR    block_device    {"ip": "198.51.100.140"}
    ${id}=    Set Variable    ${r['structuredContent']['id']}
    ${f}=    Set Variable    ${MROOT}/var/lib/rp/agent/actions/${id}.json
    ${j}=    Get File    ${f}
    ${j}=    Replace String    ${j}    198.51.100.140    192.0.2.1
    Create File    ${f}    ${j}
    ${x}=    Run Expecting    1    ${RPCTL}    --config    ${MCFG}    --root    ${MROOT}
    ...    --record-commands    ${MROOT}/tamper.log    approve    ${id}
    Should Contain    ${x.stdout}    request no longer valid
    ${cmds}=    Get File    ${MROOT}/tamper.log
    Should Not Contain    ${cmds}    nft

Action Ids Cannot Escape The Store
    ${x}=    Run Expecting    1    ${RPCTL}    --config    ${MCFG}    --root    ${MROOT}    approve
    ...    ../../../../etc/passwd
    Should Contain    ${x.stdout}    no action with id

Unauthenticated And Wrong-Token Requests Are Rejected
    ${none}=    MCP    ${EMPTY}    tools/list
    Should Be Equal As Integers    ${none['status']}    401
    Set Environment Variable    RP_TEST_BOGUS    rpt_${{ '0' * 64 }}
    ${bad}=    MCP    RP_TEST_BOGUS    tools/list
    Should Be Equal As Integers    ${bad['status']}    401
    ${agent}=    Agent Direct    POST    /v1/health
    Should Be Equal As Integers    ${agent['status']}    401
    ${agent_with_mcp_token}=    Agent Direct    POST    /v1/health    token_env=RP_TEST_OPERATOR
    Should Be Equal As Integers    ${agent_with_mcp_token['status']}    401

Browser Origins Are Refused (DNS Rebinding)
    ${r}=    MCP    RP_TEST_VIEWER    tools/list    {}    --header    Origin:http://evil.example
    Should Be Equal As Integers    ${r['status']}    403

Malformed JSON-RPC Is Handled Without Side Effects
    [Template]    Raw MCP Body Gives
    {not json                                                      -32700
    \[{"jsonrpc":"2.0","id":1,"method":"ping"}]                    -32600
    {"jsonrpc":"1.0","id":1,"method":"ping"}                       -32600
    {"jsonrpc":"2.0","id":{"x":1},"method":"ping"}                 -32600
    {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}     -32602

HTTP Smuggling And Oversized Bodies Are Rejected
    ${chunked}=    Raw HTTP    POST /mcp HTTP/1.1\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\n
    Should Start With    ${chunked}    HTTP/1.1 400
    ${big}=    Raw HTTP    POST /mcp HTTP/1.1\\r\\nContent-Length: 999999999\\r\\n\\r\\n
    Should Start With    ${big}    HTTP/1.1 413

Rate Limit Stops A Runaway Agent
    [Documentation]    Configured at 40 calls/minute per client for this suite.
    @{errors}=    Create List
    FOR    ${i}    IN RANGE    60
        ${r}=    Call Tool    RP_TEST_VIEWER    get_system_health
        IF    ${r['isError']}    Append To List    ${errors}    ${r['content'][0]['text']}
    END
    Should Not Be Empty    ${errors}
    Should Contain    ${errors[0]}    rate limit exceeded

Every Refusal Is Audited And The Chain Verifies
    ${log}=    Get File    ${MROOT}/var/lib/rp-mcp/audit.jsonl
    ${denied}=    Evaluate    sum(1 for l in $log.splitlines() if '"decision":"denied"' in l)
    Should Be True    ${denied} >= 20    msg=only ${denied} denials audited
    Should Not Contain    ${log}    rm -rf    msg=raw arguments must not be stored
    Run Ok    ${RPCTL}    --config    ${MCFG}    --root    ${MROOT}    audit    verify

Audit Tampering Is Detected
    ${p}=    Set Variable    ${MROOT}/var/lib/rp-mcp/audit.jsonl
    ${log}=    Get File    ${p}
    ${forged}=    Replace String    ${log}    "decision":"denied"    "decision":"allowed"    count=1
    Create File    ${p}    ${forged}
    ${r}=    Run Expecting    1    ${RPCTL}    --config    ${MCFG}    --root    ${MROOT}    audit    verify
    Should Contain    ${r.stdout}    BROKEN at line
    Create File    ${p}    ${log}

*** Keywords ***
Raw HTTP
    [Documentation]    Send raw bytes to the MCP port and return the first response line.
    [Arguments]    ${request}
    ${host}    ${port}=    Evaluate    $MCP_ADDR.split(':')
    ${code}=    Catenate    SEPARATOR=\n
    ...    import socket
    ...    s = socket.create_connection(('${host}', ${port}))
    ...    s.sendall(b'${request}')
    ...    print(s.recv(64).decode().splitlines()[0])
    ${r}=    Run Process    python3    -c    ${code}
    RETURN    ${r.stdout}

Scan Is Refused
    [Arguments]    ${target}    ${why}
    ${r}=    Call Tool    RP_TEST_OPERATOR    scan_network    {"target": "${target}"}
    Should Be Equal    ${r['isError']}    ${True}    msg=${target} was accepted
    Should Contain    ${r['content'][0]['text']}    ${why}

Operator Call Is Refused
    [Arguments]    ${tool}    ${args}    ${why}
    ${r}=    Call Tool    RP_TEST_OPERATOR    ${tool}    ${args}
    Should Be Equal    ${r['isError']}    ${True}    msg=${tool} ${args} was accepted
    Should Contain    ${r['content'][0]['text']}    ${why}

Raw MCP Body Gives
    [Arguments]    ${body}    ${code}
    ${r}=    Run Process    ${PROBE}    mcp    --addr    ${MCP_ADDR}    --token-env    RP_TEST_VIEWER
    ...    --method    x    --raw    ${body}
    ${j}=    Evaluate    json.loads($r.stdout)    modules=json
    Should Be Equal As Integers    ${j['body']['error']['code']}    ${code}    msg=${body}: ${j}
