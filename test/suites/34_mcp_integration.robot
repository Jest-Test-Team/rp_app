*** Settings ***
Documentation     MCP end to end on loopback: rp-mcp (HTTP + stdio) -> rp-agent (fixture root).
...               Protocol behaviour, every read tool, capability enforcement, the privileged
...               request flow up to human approval, output sanitisation and auditing.
Resource          ../resources/mcp.resource
Resource          ../resources/rpctl.resource
Suite Setup       Start Agent And MCP
Suite Teardown    Stop Agent And MCP
Test Tags         integration    mcp

*** Test Cases ***
Initialize Negotiates A Supported Protocol Version
    ${r}=    MCP    RP_TEST_VIEWER    initialize    {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "robot", "version": "1"}}
    Should Be Equal    ${r['body']['result']['protocolVersion']}    2025-06-18
    Should Be Equal    ${r['body']['result']['serverInfo']['name']}    rp-mcp
    Should Contain    ${r['body']['result']['instructions']}    untrusted data
    ${old}=    MCP    RP_TEST_VIEWER    initialize    {"protocolVersion": "1999-01-01"}
    Should Be Equal    ${old['body']['result']['protocolVersion']}    2025-06-18

Notifications Get No Reply
    ${r}=    MCP    RP_TEST_VIEWER    notifications/initialized    {}    --notify
    Should Be Equal As Integers    ${r['status']}    202

Tools List Advertises All Tools With Strict Schemas
    ${r}=    MCP    RP_TEST_VIEWER    tools/list
    ${tools}=    Set Variable    ${r['body']['result']['tools']}
    Length Should Be    ${tools}    12
    ${names}=    Evaluate    [t['name'] for t in $tools]
    FOR    ${n}    IN    get_system_health    get_device_inventory    scan_network    block_device    isolate_client
        Should Contain    ${names}    ${n}
    END
    FOR    ${t}    IN    @{tools}
        Should Be Equal    ${t['inputSchema']['additionalProperties']}    ${False}
    END
    Should Not Contain    ${names}    approve    msg=there must be no way to approve over MCP

Every Read Tool Works For A Read-Only Client
    FOR    ${tool}    IN    get_system_health    get_device_inventory    inspect_arp_table    inspect_usb
    ...    get_vpn_status    query_dns_events    get_flows    get_audit_log    list_pending_actions
        ${res}=    Call Tool    RP_TEST_VIEWER    ${tool}
        Should Be Equal    ${res['isError']}    ${False}    msg=${tool}: ${res}
    END

Health And Flows Reflect The Device
    ${h}=    Call Tool    RP_TEST_VIEWER    get_system_health
    Should Be Equal As Numbers    ${h['structuredContent']['temperature_c']}    46.0
    ${f}=    Call Tool    RP_TEST_VIEWER    get_flows
    Should Be Equal As Integers    ${f['structuredContent']['flows'][0]['dport']}    443

Inventory Sanitises Device-Supplied Names
    ${r}=    Call Tool    RP_TEST_VIEWER    get_device_inventory
    ${by_ip}=    Evaluate    {d['ip']: d for d in $r['structuredContent']['devices']}
    Should Be Equal    ${by_ip['198.51.100.140']['hostname']}    <invalid>
    Should Not Contain    ${r['content'][0]['text']}    <script>
    ${usb}=    Call Tool    RP_TEST_VIEWER    inspect_usb
    Should Be Equal    ${usb['structuredContent']['devices'][0]['product']}    802.11n WLAN Adapter

Read-Only Client Cannot Scan Or Request Privileged Actions
    ${s}=    Call Tool    RP_TEST_VIEWER    scan_network    {"target": "192.0.2.0/24"}
    Should Be Equal    ${s['isError']}    ${True}
    Should Contain    ${s['content'][0]['text']}    not allowed to use active tools
    ${b}=    Call Tool    RP_TEST_VIEWER    block_device    {"ip": "198.51.100.140"}
    Should Contain    ${b['content'][0]['text']}    not allowed to use privileged tools

Privileged Request Waits For Human Approval And Changes Nothing
    ${r}=    Call Tool    RP_TEST_OPERATOR    block_device    {"ip": "198.51.100.141", "ttl_minutes": 30, "reason": "suspicious traffic"}
    Should Be Equal    ${r['isError']}    ${False}
    Should Be Equal    ${r['structuredContent']['status']}    pending_approval
    Should Contain    ${r['structuredContent']['how_to_approve']}    sudo rpctl approve
    ${id}=    Set Variable    ${r['structuredContent']['id']}
    ${p}=    Call Tool    RP_TEST_VIEWER    list_pending_actions
    ${states}=    Evaluate    {a['id']: a['status'] for a in $p['structuredContent']['actions']}
    Should Be Equal    ${states['${id}']}    pending
    Set Suite Variable    ${PENDING_ID}    ${id}

A Person Approves On The Device And The Block Is Applied With A Timeout
    ${out}=    Run Ok    ${RPCTL}    --config    ${MCFG}    --root    ${MROOT}
    ...    --record-commands    ${MROOT}/cmds.log    approve    ${PENDING_ID}
    Should Contain    ${out}    approved and applied
    ${cmds}=    Get File    ${MROOT}/cmds.log
    Should Contain    ${cmds}    nft add element inet rp ap_quarantine4 { 198.51.100.141 timeout 30m }
    ${again}=    Run Expecting    1    ${RPCTL}    --config    ${MCFG}    --root    ${MROOT}
    ...    --record-commands    ${MROOT}/cmds.log    approve    ${PENDING_ID}
    Should Contain    ${again.stdout}    not pending

Approved Quarantine Is Restored After A Firewall Reload
    Remove File    ${MROOT}/cmds.log
    ${out}=    Run Ok    ${RPCTL}    --config    ${MCFG}    --root    ${MROOT}
    ...    --record-commands    ${MROOT}/cmds.log    quarantine-restore
    Should Contain    ${out}    restored 1 active quarantine
    ${cmds}=    Get File    ${MROOT}/cmds.log
    Should Match Regexp    ${cmds}    ap_quarantine4 \\{ 198\\.51\\.100\\.141 timeout (29|30)m \\}

Denied Requests Never Execute
    ${r}=    Call Tool    RP_TEST_OPERATOR    isolate_client    {"mac": "02:aa:bb:cc:dd:03"}
    ${id}=    Set Variable    ${r['structuredContent']['id']}
    Run Ok    ${RPCTL}    --config    ${MCFG}    --root    ${MROOT}    deny    ${id}
    ${x}=    Run Expecting    1    ${RPCTL}    --config    ${MCFG}    --root    ${MROOT}
    ...    --record-commands    ${MROOT}/cmds2.log    approve    ${id}
    Should Contain    ${x.stdout}    not pending
    ${cmds}=    Get File    ${MROOT}/cmds2.log
    Should Not Contain    ${cmds}    nft

Every Call Is In A Verifiable Audit Chain
    ${out}=    Run Ok    ${RPCTL}    --config    ${MCFG}    --root    ${MROOT}    audit    verify
    Should Contain    ${out}    agent/audit.jsonl: OK
    Should Contain    ${out}    rp-mcp/audit.jsonl: OK
    ${log}=    Get File    ${MROOT}/var/lib/rp-mcp/audit.jsonl
    Should Contain    ${log}    "decision":"denied"
    Should Contain    ${log}    "decision":"pending"
    Should Not Contain    ${log}    suspicious traffic    msg=arguments are stored as digests

Stdio Transport Works And Defaults To Read-Only
    ${input}=    Catenate    SEPARATOR=\n
    ...    {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
    ...    {"jsonrpc":"2.0","method":"notifications/initialized"}
    ...    {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_system_health","arguments":{}}}
    ...    {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_network","arguments":{"target":"192.0.2.0/24"}}}
    ${r}=    Run Process    ${MCPBIN}    --config    ${MCFG}    --root    ${MROOT}    --stdio
    ...    stdin=${input}\n    timeout=20s
    @{lines}=    Split To Lines    ${r.stdout}
    Length Should Be    ${lines}    3    msg=notification must not be answered: ${r.stdout}
    ${health}=    Evaluate    json.loads($lines[1])    modules=json
    Should Be Equal    ${health['result']['isError']}    ${False}
    ${scan}=    Evaluate    json.loads($lines[2])    modules=json
    Should Be Equal    ${scan['result']['isError']}    ${True}
