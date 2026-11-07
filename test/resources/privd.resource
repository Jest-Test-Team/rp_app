*** Settings ***
Documentation     Run rp-privd on a unix socket against a fake root (commands recorded,
...               never executed) and talk to it with rp-probe.
Resource          rpctl.resource

*** Variables ***
${PRIVD}          %{RP_PRIVD=${REPO}${/}target${/}debug${/}rp-privd}

*** Keywords ***
Start Privd
    [Documentation]    Fake device + rp-privd. Sets ${ROOT} ${CFG} ${SOCK} ${DEV} for the suite.
    [Arguments]    ${allow_me}=${True}    ${idle}=0    ${alias}=privd
    ${root}=    Create Fake Root
    Create File    ${root}/sys/class/net/eth0/device/vendor    x
    Create File    ${root}/var/lib/rp-api/tls/cert.der    robot-test-certificate
    Create File    ${root}/etc/hostname    rp-test\n
    Copy File    ${FIXTURES}/config/agent.toml    ${root}/rp.toml
    ${uid}=    Evaluate    os.getuid()    modules=os
    # Unix socket paths are limited to ~104 bytes: keep the socket short.
    ${sockdir}=    Evaluate    tempfile.mkdtemp(prefix='rpp')    modules=tempfile
    ${sock}=    Set Variable    ${sockdir}/p.sock
    @{allow}=    Create List
    IF    ${allow_me}    Append To List    ${allow}    --allow-uid    ${uid}
    Start Process    ${PRIVD}    --socket    ${sock}    --config    ${root}/rp.toml    --root    ${root}
    ...    --allow-user    nobody-rp-test    @{allow}    --idle-secs    ${idle}    --rpctl    ${RPCTL}
    ...    --record-commands    ${root}/cmds.log
    ...    --fake-output    id -u\=0    --fake-output    dpkg-query\=install ok installed
    ...    --fake-output    uname -m\=armv7l
    ...    alias=${alias}    stdout=${root}/privd.out    stderr=STDOUT
    ...    env:SSH_CONNECTION=${EMPTY}    # like systemd: no SSH session to check for lockout
    Wait Until Created    ${sock}    timeout=10s
    Set Suite Variable    ${ROOT}    ${root}
    Set Suite Variable    ${CFG}    ${root}/rp.toml
    Set Suite Variable    ${SOCK}    ${sock}
    IF    ${allow_me}
        ${info}=    Privd    {"op": "info"}
        Set Suite Variable    ${DEV}    ${info['result']['device_id']}
    END
    RETURN    ${sock}

Stop Privd
    Terminate All Processes    kill=True

Privd
    [Documentation]    Send one request (JSON text); return the parsed response.
    [Arguments]    ${request}    ${sock}=${SOCK}
    ${out}=    Run Ok    ${PROBE}    console    privd    --socket    ${sock}    --request    ${request}
    ${r}=    Evaluate    json.loads($out)    modules=json
    RETURN    ${r}

Privd Raw
    [Arguments]    ${hex}
    ${out}=    Run Ok    ${PROBE}    console    privd    --socket    ${SOCK}    --raw-hex    ${hex}
    ${r}=    Evaluate    json.loads($out)    modules=json
    RETURN    ${r}

Signed
    [Documentation]    Sign ${payload} with test key ${seed} and send it.
    [Arguments]    ${seed}    ${payload}    ${nonce}=${EMPTY}    ${device}=${DEV}    ${expires_at}=${EMPTY}
    ${env}=    Sign    ${seed}    ${payload}    ${nonce}    ${device}    ${expires_at}
    ${r}=    Send Envelope    ${env}
    RETURN    ${r}

Sign
    [Arguments]    ${seed}    ${payload}    ${nonce}=${EMPTY}    ${device}=${DEV}    ${expires_at}=${EMPTY}
    ${n}=    Evaluate    $nonce or secrets.token_hex(16)    modules=secrets
    @{exp}=    Create List
    IF    '${expires_at}' != ''    Append To List    ${exp}    --expires-at    ${expires_at}
    ${env}=    Run Ok    ${PROBE}    console    sign    --seed    ${seed}    --device    ${device}
    ...    --nonce    ${n}    --payload    ${payload}    @{exp}
    RETURN    ${env.strip()}

Send Envelope
    [Arguments]    ${env}    ${peer}=192.0.2.10
    ${r}=    Privd    {"op": "signed", "req": ${env}, "peer": "${peer}"}
    RETURN    ${r}

Pair Test Key
    [Documentation]    Open pairing with rpctl and pair test key ${seed}. Returns the response.
    [Arguments]    ${seed}    ${name}=robot
    ${out}=    Run Ok    ${RPCTL}    --config    ${CFG}    --root    ${ROOT}    pairing    new    --no-qr
    ${secret}=    Get Regexp Matches    ${out}    code\\s+([0-9a-f]{64})    1
    ${pk}=    Run Ok    ${PROBE}    console    pubkey    --seed    ${seed}
    ${pk}=    Set Variable    ${pk.strip()}
    ${nonce}=    Evaluate    secrets.token_hex(16)    modules=secrets
    ${proof}=    Run Ok    ${PROBE}    console    pair-proof    --secret    ${secret}[0]
    ...    --device    ${DEV}    --pubkey    ${pk}    --nonce    ${nonce}
    ${r}=    Privd    {"op": "pair", "name": "${name}", "public_key": "${pk}", "client_nonce": "${nonce}", "proof": "${proof.strip()}"}
    IF    ${r['ok']}
        ${expect}=    Run Ok    ${PROBE}    console    server-proof    --secret    ${secret}[0]
        ...    --device    ${DEV}    --pubkey    ${pk}    --nonce    ${nonce}
        ...    --cert    ${r['result']['cert_sha256']}    --admin    ${r['result']['admin_id']}
        Should Be Equal    ${r['result']['server_proof']}    ${expect.strip()}
    END
    RETURN    ${r}

Error Code Should Be
    [Arguments]    ${r}    ${code}
    Should Not Be True    ${r['ok']}    msg=expected error ${code}, got ${r}
    Should Be Equal    ${r['error']['code']}    ${code}
