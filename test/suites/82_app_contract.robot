*** Settings ***
Documentation     The app's Dart client against the real rp-api (fake device, real TLS, real
...               rp-privd logic): pin enforcement, pairing proofs, every read endpoint, change
...               sets (confirm, device-side rollback, conflicts, lockout refusal), secrets,
...               approvals, MCP clients, replay, WireGuard peers and admin revocation.
Resource          ../resources/app.resource
Suite Setup       Start Contract API
Suite Teardown    Stop Fake API
Test Tags         integration    app    mobile    contract

*** Variables ***
${CONTRACT_SECRET}    ${EMPTY}

*** Test Cases ***
Dart Client Passes The Contract Against rp-api
    ${r}=    Run App Tests    test/contract/api_contract_test.dart
    ...    RP_FAKE_API=${ADDR}    RP_FAKE_PIN=${PIN}    RP_FAKE_SECRET=${CONTRACT_SECRET}
    Should Be Equal As Integers    ${r['skipped']}    0    msg=contract tests were skipped
    Should Be True    ${r['passed']} >= 15

The Contract Left An Intact Audit Chain On The Device
    ${out}=    Run Ok    ${RPCTL}    --config    ${FAKE_ROOT}/etc/rp/rp.toml    --root    ${FAKE_ROOT}    audit    verify
    Should Match Regexp    ${out}    privd/audit.jsonl: OK \\(\\d+ entries\\)
    ${log}=    Get File    ${FAKE_ROOT}/var/lib/rp/privd/audit.jsonl
    Should Not Contain    ${log}    contract horse

*** Keywords ***
Start Contract API
    Require Flutter
    ${s}=    Evaluate    secrets.token_hex(32)    modules=secrets
    Set Suite Variable    ${CONTRACT_SECRET}    ${s}
    Start Fake API    secret=${s}
