*** Settings ***
Documentation     rpctl agent module and MCP client management: sandboxed units (golden),
...               tokens shown once and stored only as hashes in a 0600 file, revocation.
Resource          ../resources/rpctl.resource
Test Tags         cli    mcp

*** Variables ***
${AGCFG}          ${FIXTURES}/config/agent.toml

*** Test Cases ***
Rendered Agent Units Match Golden Copies
    ${out}=    New Temp Dir
    Run Ok    ${RPCTL}    --config    ${AGCFG}    render    agent    --out    ${out}
    @{files}=    List Files Recursively    ${FIXTURES}/golden/agent
    Length Should Be    ${files}    2
    FOR    ${rel}    IN    @{files}
        ${want}=    Get File    ${FIXTURES}/golden/agent/${rel}
        ${got}=    Get File    ${out}/${rel}
        Should Be Equal    ${got}    ${want}    msg=${rel} differs from golden copy
    END

MCP Service Has No Privileges And Gets Secrets As Credentials
    ${out}=    Run Ok    ${RPCTL}    --config    ${AGCFG}    render    agent
    Should Contain    ${out}    DynamicUser=yes
    Should Contain    ${out}    CapabilityBoundingSet=\n
    Should Contain    ${out}    LoadCredential=agent-token:/etc/rp/agent.token
    Should Contain    ${out}    CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN

Client Token Is Shown Once And Only Its Hash Is Stored
    ${root}=    Create Fake Root
    ${out}=    Run Ok    ${RPCTL}    --config    ${AGCFG}    --root    ${root}    mcp    add-client    claude
    ...    --cap    read,active
    ${tok}=    Get Regexp Matches    ${out}    rpt_[0-9a-f]{64}
    Length Should Be    ${tok}    1
    ${file}=    Get File    ${root}/etc/rp/mcp-clients.toml
    Should Not Contain    ${file}    ${tok[0]}
    ${hash}=    Evaluate    hashlib.sha256($tok[0].encode()).hexdigest()    modules=hashlib
    Should Contain    ${file}    ${hash}
    ${mode}=    Evaluate    oct(os.stat($root + '/etc/rp/mcp-clients.toml').st_mode & 0o777)    modules=os
    Should Be Equal    ${mode}    0o600
    ${list}=    Run Ok    ${RPCTL}    --config    ${AGCFG}    --root    ${root}    mcp    clients
    Should Contain    ${list}    read,active
    Should Not Contain    ${list}    ${hash}

Client Names And Capabilities Are Validated
    ${root}=    Create Fake Root
    Run Ok    ${RPCTL}    --config    ${AGCFG}    --root    ${root}    mcp    add-client    a
    ${dup}=    Run Expecting    1    ${RPCTL}    --config    ${AGCFG}    --root    ${root}    mcp    add-client    a
    Should Contain    ${dup.stdout}    exists
    ${cap}=    Run Expecting    1    ${RPCTL}    --config    ${AGCFG}    --root    ${root}    mcp    add-client    b
    ...    --cap    root
    Should Contain    ${cap.stdout}    unknown capability
    ${name}=    Run Expecting    1    ${RPCTL}    --config    ${AGCFG}    --root    ${root}    mcp    add-client
    ...    x;y
    Should Contain    ${name.stdout}    client name

Revoked Clients Disappear
    ${root}=    Create Fake Root
    Run Ok    ${RPCTL}    --config    ${AGCFG}    --root    ${root}    mcp    add-client    temp
    Run Ok    ${RPCTL}    --config    ${AGCFG}    --root    ${root}    mcp    remove-client    temp
    ${list}=    Run Ok    ${RPCTL}    --config    ${AGCFG}    --root    ${root}    mcp    clients
    Should Not Contain    ${list}    temp
    ${again}=    Run Expecting    1    ${RPCTL}    --config    ${AGCFG}    --root    ${root}    mcp
    ...    remove-client    temp
    Should Contain    ${again.stdout}    no client named

Agent Requires Base And Generates Its Token On The Device
    ${root}=    Create Fake Root
    ${needs}=    Rpctl    ${root}    1    apply    agent    config=${AGCFG}
    Should Contain    ${needs}    needs 'base' applied first
    Rpctl    ${root}    0    apply    base    config=${AGCFG}
    Remove File    ${root}/cmds.log
    ${out}=    Rpctl    ${root}    0    apply    agent    config=${AGCFG}
    Should Contain    ${out}    rpctl mcp add-client
    ${gen}=    Index Of Command    ${root}    sh -c umask 077 && [ -s '/etc/rp/agent.token' ]
    ${start}=    Index Of Command    ${root}    systemctl restart rp-agent.service
    Should Be True    ${gen} < ${start}
