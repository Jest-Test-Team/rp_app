*** Settings ***
Documentation     rp-api over real TLS (rp-api --fake: the real rp-privd logic on a simulated
...               device). Certificate pinning, no plaintext, sessions, one-time pairing with
...               mutual proof, signed changes bound to the URL and the device, replay and
...               forgery, secrets never echoed, structured errors, limits and headers.
Resource          ../resources/api.resource
Suite Setup       Start Fake API
Suite Teardown    Stop Fake API
Test Tags         security    api

*** Test Cases ***
TLS Certificate Matches The Pin And A Wrong Pin Is Refused
    ${r}=    HTTPS    GET    /v1/info
    Status Should Be    ${r}    200
    Should Be Equal    ${r['cert_sha256']}    ${PIN}
    Should Be Equal    ${r['body']['cert_sha256']}    ${PIN}
    ${bad}=    HTTPS    GET    /v1/info    pin=${{ '0' * 64 }}
    Should Contain    ${bad['tls_error']}    pin mismatch
    Should Be Equal As Integers    ${bad['status']}    0

Plain HTTP Gets No API Response
    ${code}=    Catenate    SEPARATOR=\n
    ...    import socket
    ...    s = socket.create_connection(('127.0.0.1', int('${ADDR}'.split(':')[1])), timeout=3)
    ...    s.sendall(b'GET /v1/info HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n')
    ...    try:
    ...    \ \ \ \ d = s.recv(4096)
    ...    except Exception:
    ...    \ \ \ \ d = b''
    ...    print('HTTP/1.1 200' in d.decode('latin1'))
    ${r}=    Run Process    python3    -c    ${code}
    Should Be Equal    ${r.stdout.strip()}    False

Info Is Public And Reveals No Secrets
    ${r}=    HTTPS    GET    /v1/info
    Should Be True    ${r['body']['pairing_open']}
    Should Not Contain    ${r['body']}    secret
    Should Not Contain    ${{ str($r) }}    ${SECRET}

Every Protected Endpoint Needs A Session
    ${spec}=    HTTPS    GET    /v1/openapi.json
    ${count}=    Set Variable    ${0}
    FOR    ${path}    ${item}    IN    &{spec['body']['paths']}
        ${get}=    Evaluate    $item.get('get')
        IF    $get is None or 'security' not in $get    CONTINUE
        ${p}=    Evaluate    $path.replace('{id}', 'aaaaaaaaaaaaaaaa').replace('{name}', 'x')
        ${r}=    HTTPS    GET    ${p}
        Status Should Be    ${r}    401    unauthorized
        ${r}=    HTTPS    GET    ${p}    token=rps_${{ 'f' * 64 }}
        Status Should Be    ${r}    401    unauthorized
        ${count}=    Evaluate    ${count} + 1
    END
    Should Be True    ${count} >= 20    msg=only ${count} protected endpoints found

Wrong Pairing Proof Is Refused
    ${r}=    Pair    5    secret=${{ 'ab' * 32 }}
    Status Should Be    ${r}    401    unauthorized

Pairing Proves Both Sides And Works Once
    ${r}=    Pair    1
    Status Should Be    ${r}    200
    Should Be Equal    ${r['body']['cert_sha256']}    ${PIN}
    ${again}=    Pair    2
    Status Should Be    ${again}    403    pairing_closed
    ${info}=    HTTPS    GET    /v1/info
    Should Be True    ${info['body']['paired']}

Session Works And Its Envelope Cannot Be Replayed
    ${env}=    Envelope    1    {"op": "session"}
    ${r}=    HTTPS    POST    /v1/session    ${env}
    Status Should Be    ${r}    200
    Should Start With    ${r['body']['token']}    rps_
    ${me}=    HTTPS    GET    /v1/me    token=${r['body']['token']}
    Should Be Equal    ${me['body']['name']}    robot
    ${replay}=    HTTPS    POST    /v1/session    ${env}
    Status Should Be    ${replay}    401    unauthorized

Unknown Keys And Other Devices Cannot Sign
    ${env}=    Envelope    9    {"op": "session"}
    ${r}=    HTTPS    POST    /v1/session    ${env}
    Status Should Be    ${r}    401    unauthorized
    ${env}=    Envelope    1    {"op": "session"}    device=ffffffffffffffffffffffffffffffff
    ${r}=    HTTPS    POST    /v1/session    ${env}
    Status Should Be    ${r}    401    unauthorized

Signed Operation Is Bound To The URL
    ${env}=    Envelope    1    {"op": "confirm", "id": "aaaaaaaaaaaaaaaa"}
    ${r}=    HTTPS    POST    /v1/changesets/bbbbbbbbbbbbbbbb/confirm    ${env}
    Status Should Be    ${r}    400    bad_request
    ${r}=    HTTPS    POST    /v1/session    ${env}
    Status Should Be    ${r}    400    bad_request
    ${env}=    Envelope    1    {"op": "set_secret", "name": "ap_passphrase", "value": "correct horse"}
    ${r}=    HTTPS    PUT    /v1/secrets/tailscale_auth_key    ${env}
    Status Should Be    ${r}    400    bad_request

Tampered Envelope Is Refused
    ${env}=    Envelope    1    {"op": "set_secret", "name": "ap_passphrase", "value": "correct horse"}
    ${bad}=    Evaluate    $env.replace('correct horse', 'evil horse!!')
    ${r}=    HTTPS    PUT    /v1/secrets/ap_passphrase    ${bad}
    Status Should Be    ${r}    401    unauthorized

Secrets Are Never Echoed
    ${env}=    Envelope    1    {"op": "set_secret", "name": "ap_passphrase", "value": "correct horse"}
    ${r}=    HTTPS    PUT    /v1/secrets/ap_passphrase    ${env}
    Status Should Be    ${r}    200
    ${tok}=    Session    1
    FOR    ${p}    IN    /v1/status    /v1/config    /v1/modules/ap/config    /v1/audit/events    /v1/changesets
        ${x}=    HTTPS    GET    ${p}    token=${tok}
        Status Should Be    ${x}    200
        Should Not Contain    ${{ str($x) }}    horse    msg=${p} leaked the passphrase
    END
    ${st}=    HTTPS    GET    /v1/status    token=${tok}
    Should Be True    ${st['body']['secrets']['ap_passphrase']}

MCP Token Is Not A Console Session
    ${env}=    Envelope    1    {"op": "mcp_add_client", "name": "probe", "capabilities": ["read"]}
    ${r}=    HTTPS    POST    /v1/mcp/clients    ${env}
    Status Should Be    ${r}    200
    ${mcp}=    Set Variable    ${r['body']['token']}
    ${x}=    HTTPS    GET    /v1/status    token=${mcp}
    Status Should Be    ${x}    401    unauthorized

Errors Are Structured
    ${r}=    HTTPS    GET    /v1/does-not-exist
    Status Should Be    ${r}    404    not_found
    ${r}=    HTTPS    POST    /v1/session    {not json
    Status Should Be    ${r}    400    bad_request
    ${r}=    HTTPS    POST    /v1/session    {"admin_id": "x", "extra": 1}
    Should Be True    400 <= ${r['status']} < 500
    Should Be Equal    ${r['body']['error']['code']}    bad_request
    ${tok}=    Session    1
    ${r}=    HTTPS    GET    /v1/changesets/..%2f..%2fetc%2fpasswd    token=${tok}
    Status Should Be    ${r}    404    not_found

Oversized Bodies Are Refused
    ${big}=    Evaluate    '{"name": "' + 'x' * 300000 + '"}'
    ${r}=    HTTPS    POST    /v1/pairing    ${big}
    Status Should Be    ${r}    413    too_large

Responses Are Not Cacheable Or Sniffable
    ${r}=    HTTPS    GET    /v1/info
    Should Be Equal    ${r['headers']['cache-control']}    no-store
    Should Be Equal    ${r['headers']['x-content-type-options']}    nosniff

Pairing Attempts Are Rate Limited
    FOR    ${i}    IN RANGE    12
        ${r}=    HTTPS    POST    /v1/pairing    {"name": "x", "public_key": "x", "client_nonce": "00", "proof": "00"}
    END
    Status Should Be    ${r}    429    rate_limited

Silent Clients Are Disconnected
    [Documentation]    A TLS client that never sends a request is dropped (header read timeout).
    ${code}=    Catenate    SEPARATOR=\n
    ...    import socket, ssl, time
    ...    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    ...    s = ctx.wrap_socket(socket.create_connection(('127.0.0.1', int('${ADDR}'.split(':')[1]))), server_hostname='x')
    ...    s.settimeout(20); t = time.time()
    ...    try:
    ...    \ \ \ \ s.recv(1)
    ...    except Exception:
    ...    \ \ \ \ pass
    ...    print(int(time.time() - t))
    ${r}=    Run Process    python3    -c    ${code}
    ${secs}=    Convert To Integer    ${r.stdout.strip()}
    Should Be True    ${secs} <= 15    msg=connection held for ${secs}s
