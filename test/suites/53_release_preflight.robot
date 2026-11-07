*** Settings ***
Documentation     Release preflight (deploy/release-preflight.sh): a publish that would fail or
...               ship the wrong code is refused in seconds, before anything is built, with
...               every problem and its fix listed. Dry runs never publish.
Resource          ../resources/common.resource
Test Tags         installer    release

*** Variables ***
${SCRIPT}         ${REPO}/deploy/release-preflight.sh
${HEAD}           1111111111111111111111111111111111111111
${OTHER}          2222222222222222222222222222222222222222

*** Test Cases ***
A Manual Publish Of A Missing Tag Is Refused Before Building
    [Documentation]    The run that failed after 7 minutes: publish=true, tag v0.0.1 (no such
    ...                tag, and not the workspace version 0.2.0).
    ${r}=    Preflight    1    EVENT=workflow_dispatch    PUBLISH_INPUT=true    TAG_INPUT=v0.0.1
    Should Contain    ${r}    tag v0.0.1 does not match the workspace version 0.2.0
    Should Contain    ${r}    tag v0.0.1 does not exist
    Should Contain    ${r}    git tag -a v0.0.1 -m v0.0.1 1111111 && git push origin v0.0.1
    Should Contain    ${r}    2 problem(s); nothing was built or published

Publish Without A Tag Suggests The Right One
    ${r}=    Preflight    1    EVENT=workflow_dispatch    PUBLISH_INPUT=true    TAG_INPUT=${EMPTY}
    Should Contain    ${r}    the tag would be v0.2.0

Malformed Tags Are Refused
    FOR    ${t}    IN    0.2.0    v0.2    v0.2.0-rc.1    latest
        ${r}=    Preflight    1    EVENT=workflow_dispatch    PUBLISH_INPUT=true    TAG_INPUT=${t}
        Should Contain    ${r}    is not of the form vX.Y.Z
    END

A Tag On Another Commit Is Refused
    ${r}=    Preflight    1    EVENT=workflow_dispatch    PUBLISH_INPUT=true    TAG_INPUT=v0.2.0
    ...    TAG_SHA=${OTHER}
    Should Contain    ${r}    points at 2222222, but this run builds 1111111
    Should Contain    ${r}    Use workflow from › Tags › v0.2.0

An Existing Release Is Not Overwritten
    ${r}=    Preflight    1    EVENT=workflow_dispatch    PUBLISH_INPUT=true    TAG_INPUT=v0.2.0
    ...    TAG_SHA=${HEAD}    RELEASE_EXISTS=true
    Should Contain    ${r}    a GitHub Release v0.2.0 already exists

No Signing Key Means No Publish
    ${r}=    Preflight    1    EVENT=workflow_dispatch    PUBLISH_INPUT=true    TAG_INPUT=v0.2.0
    ...    TAG_SHA=${HEAD}    HAS_SIGNING_KEY=false
    Should Contain    ${r}    MINISIGN_SECRET_KEY is not set

A Pushed Tag That Does Not Match The Version Is Refused
    ${r}=    Preflight    1    EVENT=push    REF_NAME=v0.3.0    TAG_SHA=${HEAD}
    Should Contain    ${r}    does not match the workspace version 0.2.0

A Correct Publish Passes
    ${r}=    Preflight    0    EVENT=workflow_dispatch    PUBLISH_INPUT=true    TAG_INPUT=${SPACE}v0.2.0${SPACE}
    ...    TAG_SHA=${HEAD}
    Should Contain    ${r}    publish=true
    Should Contain    ${r}    tag=v0.2.0
    ${r}=    Preflight    0    EVENT=push    REF_NAME=v0.2.0    TAG_SHA=${HEAD}
    Should Contain    ${r}    mode=publish v0.2.0

Dry Runs Never Publish And Ignore A Bad Tag
    ${r}=    Preflight    0    EVENT=workflow_dispatch    PUBLISH_INPUT=false    TAG_INPUT=v0.0.1
    Should Contain    ${r}    publish=false
    Should Contain    ${r}    tag=v0.0.1
    ${r}=    Preflight    0    EVENT=workflow_dispatch    PUBLISH_INPUT=false    TAG_INPUT=nonsense
    Should Contain    ${r}    ignoring tag 'nonsense'
    Should Contain    ${r}    tag=\n
    ${r}=    Preflight    0    EVENT=pull_request    REF_NAME=6/merge    HAS_SIGNING_KEY=false
    Should Contain    ${r}    publish=false
    Should Contain    ${r}    mode=dry run

*** Keywords ***
Preflight
    [Documentation]    Run the script with defaults (version 0.2.0, key set, no tag, no release).
    [Arguments]    ${rc}    &{facts}
    ${env}=    Create Dictionary    SHA=${HEAD}    CARGO_VERSION=0.2.0    HAS_SIGNING_KEY=true
    ...    TAG_SHA=${EMPTY}    RELEASE_EXISTS=false    PUBLISH_INPUT=false    TAG_INPUT=${EMPTY}    REF_NAME=${EMPTY}
    FOR    ${k}    ${v}    IN    &{facts}
        Set To Dictionary    ${env}    ${k}=${v}
    END
    ${full}=    Evaluate    {**os.environ, **$env}    modules=os
    ${r}=    Run Process    bash    ${SCRIPT}    env=${full}    stderr=STDOUT
    Log    ${r.stdout}
    Should Be Equal As Integers    ${r.rc}    ${rc}    msg=${r.stdout}
    RETURN    ${r.stdout}
