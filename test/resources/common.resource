*** Settings ***
Documentation     Shared variables and keywords for every rp suite.
Library           Process
Library           OperatingSystem
Library           String
Library           Collections

*** Variables ***
${REPO}           ${CURDIR}${/}..${/}..
${FIXTURES}       ${CURDIR}${/}..${/}fixtures
${RPCTL}          %{RP_RPCTL=${REPO}${/}target${/}debug${/}rpctl}
${PROBE}          %{RP_PROBE=${REPO}${/}target${/}debug${/}rp-probe}
${INSTALL_SH}     ${REPO}${/}deploy${/}install.sh
${INSTALL_PS1}    ${REPO}${/}deploy${/}install.ps1

*** Keywords ***
Run Expecting
    [Documentation]    Run a command without a shell and assert its exit code.
    ...                Returns the process result (stdout includes stderr).
    [Arguments]    ${expected_rc}    @{cmd}    &{opts}
    ${r}=    Run Process    @{cmd}    cwd=${REPO}    stderr=STDOUT    &{opts}
    Log    ${r.stdout}
    Should Be Equal As Integers    ${r.rc}    ${expected_rc}
    ...    msg=`${cmd}` exited ${r.rc}, expected ${expected_rc}:\n${r.stdout}
    RETURN    ${r}

Run Ok
    [Arguments]    @{cmd}    &{opts}
    ${r}=    Run Expecting    0    @{cmd}    &{opts}
    RETURN    ${r.stdout}

Require Tool
    [Documentation]    Skip the test when an external tool is not on PATH.
    [Arguments]    ${tool}
    ${path}=    Evaluate    shutil.which($tool) or ''    modules=shutil
    Skip If    '${path}' == ''    ${tool} is not installed
    RETURN    ${path}

New Temp Dir
    [Documentation]    Scratch dirs live under results/tmp (cleared by run.sh), never in /tmp.
    ${base}=    Evaluate    os.path.join($OUTPUT_DIR, 'tmp')    modules=os
    Create Directory    ${base}
    ${d}=    Evaluate    tempfile.mkdtemp(prefix='rp-robot-', dir=$base)    modules=tempfile
    RETURN    ${d}

Is Linux
    ${os}=    Evaluate    platform.system()    modules=platform
    RETURN    ${{ '${os}' == 'Linux' }}

Native Linux Triple
    ${m}=    Evaluate    platform.machine()    modules=platform
    ${t}=    Set Variable If
    ...    '${m}' in ('x86_64', 'AMD64')    x86_64-unknown-linux-gnu
    ...    '${m}' in ('aarch64', 'arm64')    aarch64-unknown-linux-gnu
    ...    '${m}' == 'armv7l'    armv7-unknown-linux-gnueabihf
    RETURN    ${t}

List Files Recursively
    [Documentation]    Sorted paths of all files under ${dir}, relative to it.
    [Arguments]    ${dir}
    ${files}=    Evaluate
    ...    (lambda b: sorted(str(p.relative_to(b)) for p in b.rglob('*') if p.is_file()))(pathlib.Path($dir))
    ...    modules=pathlib
    RETURN    ${files}
