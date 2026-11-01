*** Settings ***
Documentation     rp-privd as a black box over its unix socket: only allowed uids, only typed
...               operations, only admin-signed changes (no forgery, replay, cross-device or
...               expired requests), one-time pairing, secrets never logged, idle exit.
Resource          ../resources/privd.resource
Suite Setup       Start Privd
Suite Teardown    Stop Privd
Test Tags         security    privd

*** Test Cases ***
Info Is Readable And Reveals No Secrets
    ${r}=    Privd    {"op": "info"}
    Should Be True    ${r['ok']}
    Should Be Equal    ${r['result']['paired']}    ${False}
    Length Should Be    ${r['result']['device_id']}    32
    Should Not Contain    ${r}    secret

Unknown Operations And Extra Fields Are Refused
    ${r}=    Privd    {"op": "run_command", "argv": ["id"]}
    Error Code Should Be    ${r}    bad_request
    ${r}=    Privd    {"op": "info", "shell": "id"}
    Error Code Should Be    ${r}    bad_request

Malformed And Oversized Frames Are Refused
    ${r}=    Privd Raw    000000056e6f746a73
    Error Code Should Be    ${r}    bad_request
    ${r}=    Privd Raw    7fffffff00
    Error Code Should Be    ${r}    bad_request
    Should Contain    ${r['error']['message']}    too large

Changes Without A Paired Admin Are Unauthorized
    ${r}=    Signed    7    {"op": "session"}
    Error Code Should Be    ${r}    unauthorized

Pairing Needs An Open Code And Works Once
    ${r}=    Privd    {"op": "pair", "name": "x", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "client_nonce": "00112233445566778899aabbccddeeff", "proof": "00"}
    Error Code Should Be    ${r}    pairing_closed
    ${r}=    Pair Test Key    1
    Should Be True    ${r['ok']}    msg=${r}
    ${sha}=    Evaluate    hashlib.sha256(b'robot-test-certificate').hexdigest()    modules=hashlib
    Should Be Equal    ${r['result']['cert_sha256']}    ${sha}
    ${info}=    Privd    {"op": "info"}
    Should Be True    ${info['result']['paired']}
    Should Not Be True    ${info['result']['pairing_open']}

Wrong Pairing Proofs Lock Pairing
    Run Ok    ${RPCTL}    --config    ${CFG}    --root    ${ROOT}    pairing    new    --no-qr
    ${pk}=    Run Ok    ${PROBE}    console    pubkey    --seed    9
    FOR    ${i}    IN RANGE    4
        ${r}=    Privd    {"op": "pair", "name": "evil", "public_key": "${pk.strip()}", "client_nonce": "00112233445566778899aabbccddeeff", "proof": "${{ 'ab' * 32 }}"}
        Error Code Should Be    ${r}    unauthorized
    END
    ${r}=    Privd    {"op": "pair", "name": "evil", "public_key": "${pk.strip()}", "client_nonce": "00112233445566778899aabbccddeeff", "proof": "${{ 'ab' * 32 }}"}
    Error Code Should Be    ${r}    locked
    Run Ok    ${RPCTL}    --config    ${CFG}    --root    ${ROOT}    pairing    close

Signed Session Works And Replays Are Refused
    ${env}=    Sign    1    {"op": "session"}
    ${r}=    Send Envelope    ${env}
    Should Be True    ${r['ok']}
    Should Be Equal    ${r['result']['name']}    robot
    ${r}=    Send Envelope    ${env}
    Error Code Should Be    ${r}    unauthorized
    Should Contain    ${r['error']['message']}    already used

Forged Cross Device And Expired Requests Are Refused
    ${r}=    Signed    2    {"op": "session"}
    Error Code Should Be    ${r}    unauthorized
    ${r}=    Signed    1    {"op": "session"}    device=ffffffffffffffffffffffffffffffff
    Error Code Should Be    ${r}    unauthorized
    ${past}=    Evaluate    int(time.time()) - 5    modules=time
    ${r}=    Signed    1    {"op": "session"}    expires_at=${past}
    Error Code Should Be    ${r}    unauthorized
    ${far}=    Evaluate    int(time.time()) + 3600    modules=time
    ${r}=    Signed    1    {"op": "session"}    expires_at=${far}
    Error Code Should Be    ${r}    unauthorized
    ${env}=    Sign    1    {"op": "set_secret", "name": "ap_passphrase", "value": "correct horse"}
    ${tampered}=    Evaluate    $env.replace('correct horse', 'attacker pass')
    ${r}=    Send Envelope    ${tampered}
    Error Code Should Be    ${r}    unauthorized
    File Should Not Exist    ${ROOT}/etc/rp/ap.psk

Signed Change Set Is Applied With A Rollback Timer
    ${st}=    Privd    {"op": "status"}
    ${rev}=    Set Variable    ${st['result']['revision']}
    ${r}=    Signed    1    {"op": "create_changeset", "module": "base", "expected_revision": ${rev}, "patch": {"base.allow_mdns": false}}
    Should Be True    ${r['ok']}    msg=${r}
    ${id}=    Set Variable    ${r['result']['id']}
    ${r}=    Signed    1    {"op": "preflight", "id": "${id}"}
    Should Be True    ${r['ok']}    msg=${r}
    ${r}=    Signed    1    {"op": "apply", "id": "${id}"}
    Should Be Equal    ${r['result']['status']}    awaiting_confirm
    ${cmds}=    Get File    ${ROOT}/cmds.log
    Should Contain    ${cmds}    systemd-run --unit=rp-changeset-${id}
    Should Contain    ${cmds}    changeset expire ${id}
    # The device rolls back by itself: run what the timer runs.
    Run Ok    ${RPCTL}    --config    ${CFG}    --root    ${ROOT}    --record-commands    ${ROOT}/cmds2.log
    ...    changeset    expire    ${id}
    ${r}=    Privd    {"op": "get_changeset", "id": "${id}"}
    Should Be Equal    ${r['result']['status']}    rolled_back
    ${text}=    Get File    ${CFG}
    Should Not Contain    ${text}    allow_mdns

Lockout Of The App Fails Preflight
    ${st}=    Privd    {"op": "status"}
    ${r}=    Signed    1    {"op": "create_changeset", "module": "base", "expected_revision": ${st['result']['revision']}, "patch": {"base.journal_max_mb": 32}}
    ${env}=    Sign    1    {"op": "preflight", "id": "${r['result']['id']}"}
    ${r}=    Send Envelope    ${env}    peer=198.51.100.20
    Error Code Should Be    ${r}    preflight_failed

Secrets Are Stored But Never Echoed Or Audited
    ${r}=    Signed    1    {"op": "set_secret", "name": "ap_passphrase", "value": "correct horse"}
    Should Be True    ${r['ok']}
    Should Not Contain    ${r}    horse
    ${audit}=    Get File    ${ROOT}/var/lib/rp/privd/audit.jsonl
    Should Not Contain    ${audit}    horse
    Should Contain    ${audit}    set_secret
    ${r}=    Privd    {"op": "status"}
    Should Be True    ${r['result']['secrets']['ap_passphrase']}

Audit Chain Of Console Operations Verifies And Detects Tampering
    ${out}=    Run Ok    ${RPCTL}    --config    ${CFG}    --root    ${ROOT}    audit    verify
    Should Match Regexp    ${out}    privd/audit.jsonl: OK \\(\\d+ entries\\)
    ${log}=    Set Variable    ${ROOT}/var/lib/rp/privd/audit.jsonl
    Copy File    ${log}    ${log}.bak
    ${text}=    Get File    ${log}
    ${forged}=    Evaluate    $text.replace('"set_secret"', '"session"', 1)
    Create File    ${log}    ${forged}
    ${r}=    Run Expecting    1    ${RPCTL}    --config    ${CFG}    --root    ${ROOT}    audit    verify
    Should Contain    ${r.stdout}    BROKEN
    Move File    ${log}.bak    ${log}

Revoked Admin Loses Access
    ${r}=    Signed    1    {"op": "open_pairing", "valid_minutes": 5}
    ${secret}=    Set Variable    ${r['result']['secret']}
    ${pk}=    Run Ok    ${PROBE}    console    pubkey    --seed    3
    ${nonce}=    Evaluate    secrets.token_hex(16)    modules=secrets
    ${proof}=    Run Ok    ${PROBE}    console    pair-proof    --secret    ${secret}    --device    ${DEV}
    ...    --pubkey    ${pk.strip()}    --nonce    ${nonce}
    ${r}=    Privd    {"op": "pair", "name": "second", "public_key": "${pk.strip()}", "client_nonce": "${nonce}", "proof": "${proof.strip()}"}
    Should Be True    ${r['ok']}
    ${id1}=    Run Ok    ${PROBE}    console    admin-id    --seed    1
    ${r}=    Signed    3    {"op": "revoke_admin", "admin_id": "${id1.strip()}"}
    Should Be True    ${r['ok']}
    ${r}=    Signed    1    {"op": "session"}
    Error Code Should Be    ${r}    unauthorized
    ${list}=    Run Ok    ${RPCTL}    --config    ${CFG}    --root    ${ROOT}    admins    list
    Should Contain    ${list}    second
    Should Not Contain    ${list}    robot

Other Users Cannot Connect
    ${sock}=    Start Privd    allow_me=${False}    alias=strict
    ${r}=    Privd    {"op": "info"}    sock=${sock}
    Error Code Should Be    ${r}    forbidden

Privd Exits When Idle
    ${sock}=    Start Privd    idle=2    alias=idle
    ${res}=    Wait For Process    idle    timeout=15s
    Should Be Equal As Integers    ${res.rc}    0
