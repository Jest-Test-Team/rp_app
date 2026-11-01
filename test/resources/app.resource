*** Settings ***
Documentation     Keywords for the RP Security console app (Flutter) in apps/rp_console.
Resource          api.resource
Library           json_summary.py

*** Variables ***
${APP}            ${REPO}${/}apps${/}rp_console

*** Keywords ***
Require Flutter
    Require Tool    flutter

Flutter
    [Documentation]    Run flutter (or dart) in the app directory; returns the result.
    [Arguments]    ${rc}    @{args}    &{opts}
    ${r}=    Run Expecting    ${rc}    flutter    @{args}    cwd=${APP}    &{opts}
    RETURN    ${r}

Pub Get
    Require Flutter
    ${r}=    Run Process    flutter    pub    get    cwd=${APP}    stderr=STDOUT
    Should Be Equal As Integers    ${r.rc}    0    msg=${r.stdout}

Run App Tests
    [Documentation]    flutter test PATHS with a JSON report; fails on any failure and returns
    ...    {"passed", "failed", "skipped", "names"}. Extra env vars via &{env}.
    [Arguments]    @{paths}    &{env}
    Pub Get
    ${report}=    Evaluate    os.path.join($OUTPUT_DIR, 'tmp', 'flutter-' + __import__('secrets').token_hex(4) + '.json')    modules=os
    Create Directory    ${OUTPUT_DIR}${/}tmp
    ${full}=    Evaluate    {**os.environ, **$env}    modules=os
    ${r}=    Run Process    flutter    test    --file-reporter    json:${report}    @{paths}
    ...    cwd=${APP}    stderr=STDOUT    timeout=15min    env=${full}
    Log    ${r.stdout}
    ${sum}=    Summarize    ${report}
    Should Be Equal As Integers    ${r.rc}    0    msg=flutter test failed (${sum['failed']} failed):\n${r.stdout[-3000:]}
    RETURN    ${sum}

Start Second Fake API
    [Documentation]    Another simulated device (its own certificate) for impostor tests.
    [Arguments]    ${secret}
    ${root}=    New Temp Dir
    Start Process    ${RPAPI}    --fake    --fake-root    ${root}/dev    --listen    127.0.0.1:0
    ...    --ready-file    ${root}/ready.json    --fake-pairing-secret    ${secret}
    ...    alias=rp-api-impostor    stdout=${root}/api.out    stderr=STDOUT
    Wait Until Created    ${root}/ready.json    timeout=20s
    Sleep    0.2s
    ${ready}=    Evaluate    json.load(open($root + '/ready.json'))    modules=json
    RETURN    ${ready}
