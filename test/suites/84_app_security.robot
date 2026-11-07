*** Settings ***
Documentation     Security properties of the console app: platform hardening and source rules
...               (static), and at runtime that a device posing as the paired one — same
...               address, different certificate — gets nothing.
Resource          ../resources/app.resource
Suite Setup       Start Fake API
Suite Teardown    Stop Fake API
Test Tags         security    app    mobile

*** Test Cases ***
Static App Security Rules Hold
    ${r}=    Run App Tests    test/unit/platform_security_test.dart    test/unit/ssh_bootstrap_test.dart
    Should Be Equal As Integers    ${r['failed']}    0
    Should Contain    ${r['names']}    TLS: no CA is trusted and the certificate callback enforces the pin
    Should Contain    ${r['names']}    password goes only to stdin of sudo -S -v, never into a command

No Trusted Roots Anywhere The App Talks To A Device
    ${src}=    Get File    ${APP}/lib/core/api/transport.dart
    Should Contain    ${src}    SecurityContext(withTrustedRoots: false)
    ${hits}=    Run Process    grep    -rnE    badCertificateCallback\\s*\=\\s*\\([^)]*\\)\\s*\=>\\s*true    ${APP}/lib
    Should Be Empty    ${hits.stdout}

Android Never Backs Up Or Uses Cleartext
    ${m}=    Get File    ${APP}/android/app/src/main/AndroidManifest.xml
    Should Contain    ${m}    android:allowBackup="false"
    Should Contain    ${m}    android:usesCleartextTraffic="false"
    Should Contain    ${m}    android:dataExtractionRules

Keys Stay In The Platform Keystore
    ${v}=    Get File    ${APP}/lib/core/storage/vault.dart
    Should Contain    ${v}    KeychainAccessibility.unlocked_this_device
    ${hits}=    Run Process    grep    -rnlE    SharedPreferences|path_provider|writeAsString.*key    ${APP}/lib/core/storage    ${APP}/lib/core/auth
    Should Be Empty    ${hits.stdout}

An Impostor With Another Certificate Gets Nothing
    ${secret}=    Evaluate    secrets.token_hex(32)    modules=secrets
    ${imp}=    Start Second Fake API    ${secret}
    ${r}=    Run App Tests    test/contract/impostor_test.dart
    ...    RP_IMPOSTOR_API=127.0.0.1:${imp['port']}    RP_PAIRED_PIN=${PIN}    RP_IMPOSTOR_SECRET=${secret}
    Should Be Equal As Integers    ${r['skipped']}    0
    Should Be Equal As Integers    ${r['passed']}    2
    # The impostor never received a pairing request.
    ${audit}=    Run Process    cat    ${imp['root']}/var/lib/rp/privd/audit.jsonl
    Should Not Contain    ${audit.stdout}    "pair"
