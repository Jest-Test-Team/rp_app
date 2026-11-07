*** Settings ***
Documentation     Console app (Flutter, apps/rp_console): formatting, analysis with strict
...               casts and raw types, dependency hygiene and the API contract on disk.
Resource          ../resources/app.resource
Test Tags         static    app    mobile

*** Test Cases ***
Dart Code Is Formatted
    Pub Get
    Flutter    0    pub    run    --help
    ${r}=    Run Expecting    0    dart    format    --output\=none    --set-exit-if-changed    lib    test    cwd=${APP}

Flutter Analyze Reports No Issues
    Pub Get
    ${r}=    Flutter    0    analyze    --no-pub
    Should Contain    ${r.stdout}    No issues found

Dependencies Are Locked And From pub.dev Only
    ${lock}=    Get File    ${APP}/pubspec.lock
    Should Not Contain    ${lock}    source: git
    Should Not Contain    ${lock}    source: path
    ${spec}=    Get File    ${APP}/pubspec.yaml
    Should Not Contain    ${spec}    git:
    Should Not Contain    ${spec}    dependency_overrides

The App's API Contract Is The One rp-api Serves
    ${live}=    Run Ok    ${RPAPI}    openapi
    ${committed}=    Get File    ${APP}/api/openapi.json
    Should Be Equal    ${live.strip()}    ${committed.strip()}
