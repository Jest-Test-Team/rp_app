*** Settings ***
Documentation     Run rp-api --fake (real rp-privd logic on a simulated device, real TLS) and
...               talk to it over HTTPS with rp-probe, pinning its certificate.
Resource          common.resource

*** Variables ***
${RPAPI}          %{RP_API=${REPO}${/}target${/}debug${/}rp-api}
${SECRET}         0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

*** Keywords ***
Start Fake API
    [Arguments]    ${secret}=${SECRET}
    ${root}=    New Temp Dir
    Start Process    ${RPAPI}    --fake    --fake-root    ${root}/dev    --listen    127.0.0.1:0
    ...    --ready-file    ${root}/ready.json    --fake-pairing-secret    ${secret}
    ...    alias=rp-api    stdout=${root}/api.out    stderr=STDOUT
    Wait Until Created    ${root}/ready.json    timeout=20s
    Sleep    0.2s
    ${ready}=    Evaluate    json.load(open($root + '/ready.json'))    modules=json
    Set Suite Variable    ${ADDR}    127.0.0.1:${ready['port']}
    Set Suite Variable    ${PIN}    ${ready['cert_sha256']}
    Set Suite Variable    ${DEV}    ${ready['device_id']}
    Set Suite Variable    ${FAKE_ROOT}    ${ready['root']}
    Set Suite Variable    ${TMP}    ${root}

Stop Fake API
    Terminate All Processes    kill=True

HTTPS
    [Documentation]    One request; returns {status, headers, body, cert_sha256}.
    [Arguments]    ${method}    ${path}    ${body}=${EMPTY}    ${token}=${EMPTY}    ${pin}=${PIN}    @{headers}
    @{args}=    Create List    --addr    ${ADDR}    --method    ${method}    --path    ${path}
    IF    '${pin}' != 'none'    Append To List    ${args}    --pin    ${pin}
    IF    $body
        ${f}=    Evaluate    tempfile.mktemp(dir=$TMP)    modules=tempfile
        Create File    ${f}    ${body}
        Append To List    ${args}    --body-file    ${f}
    END
    FOR    ${h}    IN    @{headers}
        Append To List    ${args}    --header    ${h}
    END
    IF    $token
        Set Environment Variable    RP_TEST_TOKEN    ${token}
        Append To List    ${args}    --token-env    RP_TEST_TOKEN
    END
    ${out}=    Run Ok    ${PROBE}    https    @{args}
    ${r}=    Evaluate    json.loads($out)    modules=json
    RETURN    ${r}

Envelope
    [Arguments]    ${seed}    ${payload}    ${device}=${DEV}
    ${n}=    Evaluate    secrets.token_hex(16)    modules=secrets
    ${env}=    Run Ok    ${PROBE}    console    sign    --seed    ${seed}    --device    ${device}
    ...    --nonce    ${n}    --payload    ${payload}
    RETURN    ${env.strip()}

Pair
    [Arguments]    ${seed}    ${secret}=${SECRET}    ${name}=robot
    ${pk}=    Run Ok    ${PROBE}    console    pubkey    --seed    ${seed}
    ${nonce}=    Evaluate    secrets.token_hex(16)    modules=secrets
    ${proof}=    Run Ok    ${PROBE}    console    pair-proof    --secret    ${secret}
    ...    --device    ${DEV}    --pubkey    ${pk.strip()}    --nonce    ${nonce}
    ${r}=    HTTPS    POST    /v1/pairing
    ...    {"name": "${name}", "public_key": "${pk.strip()}", "client_nonce": "${nonce}", "proof": "${proof.strip()}"}
    IF    ${r['status']} == 200
        ${expect}=    Run Ok    ${PROBE}    console    server-proof    --secret    ${secret}
        ...    --device    ${DEV}    --pubkey    ${pk.strip()}    --nonce    ${nonce}
        ...    --cert    ${PIN}    --admin    ${r['body']['admin_id']}
        Should Be Equal    ${r['body']['server_proof']}    ${expect.strip()}    msg=device must prove the secret over the pinned certificate
    END
    RETURN    ${r}

Session
    [Arguments]    ${seed}
    ${env}=    Envelope    ${seed}    {"op": "session"}
    ${r}=    HTTPS    POST    /v1/session    ${env}
    Should Be Equal As Integers    ${r['status']}    200    msg=${r}
    RETURN    ${r['body']['token']}

Status Should Be
    [Arguments]    ${r}    ${status}    ${code}=${EMPTY}
    Should Be Equal As Integers    ${r['status']}    ${status}    msg=${r}
    IF    $code    Should Be Equal    ${r['body']['error']['code']}    ${code}
