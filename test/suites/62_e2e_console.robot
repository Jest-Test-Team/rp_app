*** Settings ***
Documentation     The console path on a real device (v0.2 installed, `sudo rpctl setup` done):
...               rp-api / rp-privd up and LAN-only, pairing a throw-away random key over pinned
...               HTTPS, signed reads, a preflighted change. Never pairs a deterministic test key;
...               the test admin is revoked in teardown.
...
...               With RP_E2E_APPLY=1 it also applies a harmless DNS change without confirming
...               and checks that the real systemd timer rolls it back.
Resource          ../resources/ssh.resource
Suite Setup       Prepare Console E2E
Suite Teardown    Clean Up Console E2E
Test Tags         e2e    requires-pi    console

*** Variables ***
${APPLY}          %{RP_E2E_APPLY=0}
${API_PORT}       8443
${ADMIN}          ${EMPTY}

*** Test Cases ***
Console Services Run And The API Is LAN Only
    On Device    systemctl is-active --quiet rp-api.service
    On Device    systemctl is-active --quiet rp-privd.socket
    ${rules}=    As Root On Device    nft list chain inet rp mod_input
    Should Match Regexp    ${rules}    tcp dport ${API_PORT} ip saddr @lan4 accept
    Should Not Match Regexp    ${rules}    tcp dport ${API_PORT} accept
    ${sock}=    On Device    stat -c '%U:%G %a' /run/rp/privd.sock
    Should Be Equal    ${sock}    root:rp-api 660

The Certificate Seen Over The Network Is The One On The Device
    ${r}=    HTTPS    GET    /v1/info
    Should Be Equal As Integers    ${r['status']}    200
    ${fp}=    As Root On Device    sha256sum /var/lib/rp-api/tls/cert.der | cut -d' ' -f1
    Should Be Equal    ${r['cert_sha256']}    ${fp}
    Set Suite Variable    ${PIN}    ${fp}
    Set Suite Variable    ${DEV}    ${r['body']['device_id']}

Pairing A Random Key Proves Both Sides
    ${code}=    As Root On Device    rpctl --json pairing new --minutes 5
    ${c}=    Evaluate    json.loads($code)    modules=json
    Should Be Equal    ${c['cert']}    ${PIN}
    ${pk}=    Run Ok    ${PROBE}    console    keygen    --out    ${KEY}
    ${nonce}=    Evaluate    secrets.token_hex(16)    modules=secrets
    ${proof}=    Run Ok    ${PROBE}    console    pair-proof    --secret    ${c['secret']}    --device    ${DEV}
    ...    --pubkey    ${pk.strip()}    --nonce    ${nonce}
    ${r}=    HTTPS    POST    /v1/pairing
    ...    {"name": "robot-e2e", "public_key": "${pk.strip()}", "client_nonce": "${nonce}", "proof": "${proof.strip()}"}
    Should Be Equal As Integers    ${r['status']}    200    msg=${r}
    Set Suite Variable    ${ADMIN}    ${r['body']['admin_id']}
    ${expect}=    Run Ok    ${PROBE}    console    server-proof    --secret    ${c['secret']}    --device    ${DEV}
    ...    --pubkey    ${pk.strip()}    --nonce    ${nonce}    --cert    ${PIN}    --admin    ${ADMIN}
    Should Be Equal    ${r['body']['server_proof']}    ${expect.strip()}
    ${again}=    HTTPS    POST    /v1/pairing
    ...    {"name": "robot-e2e", "public_key": "${pk.strip()}", "client_nonce": "${nonce}", "proof": "${proof.strip()}"}
    Should Be Equal As Integers    ${again['status']}    403

Signed Session Reads The Real Device
    ${tok}=    Session
    FOR    ${p}    IN    /v1/status    /v1/capabilities    /v1/health    /v1/dns/stats    /v1/update
        ${r}=    HTTPS    GET    ${p}    token=${tok}
        Should Be Equal As Integers    ${r['status']}    200    msg=${p}: ${r}
    END
    ${caps}=    HTTPS    GET    /v1/capabilities    token=${tok}
    Should Contain    ${caps['body']['device']['model']}    Raspberry Pi

A Change Is Preflighted On The Device Without Applying
    ${tok}=    Session
    ${st}=    HTTPS    GET    /v1/status    token=${tok}
    ${env}=    Envelope    {"op": "create_changeset", "module": "base", "expected_revision": ${st['body']['revision']}, "patch": {"base.journal_max_mb": 64}}
    ${cs}=    HTTPS    POST    /v1/changesets    ${env}
    Should Be Equal As Integers    ${cs['status']}    200    msg=${cs}
    ${env}=    Envelope    {"op": "preflight", "id": "${cs['body']['id']}"}
    ${pf}=    HTTPS    POST    /v1/changesets/${cs['body']['id']}/preflight    ${env}
    Should Be Equal As Integers    ${pf['status']}    200    msg=${pf}
    ${names}=    Evaluate    [c['name'] for c in $pf['body']['checks'] if c['status'] == 'pass']
    Should Contain    ${names}    api_lockout
    Should Contain    ${names}    capability

An Unconfirmed Change Is Rolled Back By The Real Timer
    [Tags]    destructive
    Skip If    '${APPLY}' != '1'    set RP_E2E_APPLY=1 to apply on the device
    ${before}=    As Root On Device    sha256sum /etc/rp/rp.toml
    ${tok}=    Session
    ${st}=    HTTPS    GET    /v1/status    token=${tok}
    ${env}=    Envelope    {"op": "create_changeset", "module": "dns", "expected_revision": ${st['body']['revision']}, "patch": {"dns.events_retention_days": 6}}
    ${cs}=    HTTPS    POST    /v1/changesets    ${env}
    ${id}=    Set Variable    ${cs['body']['id']}
    ${env}=    Envelope    {"op": "preflight", "id": "${id}"}
    HTTPS    POST    /v1/changesets/${id}/preflight    ${env}
    ${env}=    Envelope    {"op": "apply", "id": "${id}", "confirm_secs": 30}
    ${ap}=    HTTPS    POST    /v1/changesets/${id}/apply    ${env}
    Should Be Equal    ${ap['body']['status']}    awaiting_confirm    msg=${ap}
    Sleep    45s
    ${tok}=    Session
    ${got}=    HTTPS    GET    /v1/changesets/${id}    token=${tok}
    Should Be Equal    ${got['body']['status']}    rolled_back
    ${after}=    As Root On Device    sha256sum /etc/rp/rp.toml
    Should Be Equal    ${before}    ${after}
    On Device    systemctl is-active --quiet rp-dns.service

*** Keywords ***
Prepare Console E2E
    Open Device Connection
    ${user}    ${host}=    Evaluate    $E2E_HOST.split('@', 1)
    Set Suite Variable    ${ADDR}    ${host}:${API_PORT}
    ${tmp}=    New Temp Dir
    Set Suite Variable    ${KEY}    ${tmp}/e2e-admin.key
    ${r}=    Execute Command    systemctl is-active --quiet rp-api.service    return_stdout=False    return_rc=True
    Skip If    ${r} != 0    rp-api is not running: install v0.2 and run `sudo rpctl setup` on the device first

Clean Up Console E2E
    IF    '${ADMIN}' != ''    As Root On Device    rpctl admins revoke ${ADMIN}
    Run Keyword And Ignore Error    As Root On Device    rpctl pairing close
    Run Keyword And Ignore Error    Remove File    ${KEY}
    Close All Connections

HTTPS
    [Arguments]    ${method}    ${path}    ${body}=${EMPTY}    ${token}=${EMPTY}
    @{args}=    Create List    --addr    ${ADDR}    --method    ${method}    --path    ${path}
    ${pin}=    Get Variable Value    ${PIN}    ${EMPTY}
    IF    $pin    Append To List    ${args}    --pin    ${pin}
    IF    $body    Append To List    ${args}    --body    ${body}
    IF    $token
        Set Environment Variable    RP_E2E_SESSION    ${token}
        Append To List    ${args}    --token-env    RP_E2E_SESSION
    END
    ${out}=    Run Ok    ${PROBE}    https    @{args}
    ${r}=    Evaluate    json.loads($out)    modules=json
    RETURN    ${r}

Envelope
    [Arguments]    ${payload}
    ${n}=    Evaluate    secrets.token_hex(16)    modules=secrets
    ${env}=    Run Ok    ${PROBE}    console    sign    --key-file    ${KEY}    --device    ${DEV}
    ...    --nonce    ${n}    --payload    ${payload}
    RETURN    ${env.strip()}

Session
    ${env}=    Envelope    {"op": "session"}
    ${r}=    HTTPS    POST    /v1/session    ${env}
    Should Be Equal As Integers    ${r['status']}    200    msg=${r}
    RETURN    ${r['body']['token']}
