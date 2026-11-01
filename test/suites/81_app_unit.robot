*** Settings ***
Documentation     Console app unit and widget tests (Dart VM, no device needed): crypto and
...               SD-card files byte-identical to Rust, pairing, signing, change flow, SSH
...               bootstrap secrecy, storage, localization, and every screen against a fake device.
Resource          ../resources/app.resource
Test Tags         unit    app    mobile

*** Test Cases ***
Unit Tests Pass
    ${r}=    Run App Tests    test/unit
    Should Be True    ${r['passed']} >= 50    msg=only ${r['passed']} unit tests ran
    Should Be Equal As Integers    ${r['failed']}    0

Cross Language Golden Files Are Covered
    ${r}=    Run App Tests    test/unit/crypto_golden_test.dart    test/unit/provision_test.dart
    Should Contain    ${r['names']}    admin key, id and Ed25519 signature match rp-policy
    Should Contain    ${r['names']}    pairing proofs match rp-policy
    Should Contain    ${r['names']}    minimal card matches the Rust golden files
    Should Contain    ${r['names']}    full card matches the Rust golden files

Widget Tests Pass For Every Screen
    ${r}=    Run App Tests    test/widget
    Should Be True    ${r['passed']} >= 14    msg=only ${r['passed']} widget tests ran
    ${names}=    Evaluate    ' | '.join($r['names'])
    FOR    ${screen}    IN    pair with a code    SSH path    Chinese UI    DNS:    IoT Wi-Fi:    Firewall:    MCP:    Settings:    overview
        Should Contain    ${names}    ${screen}
    END
