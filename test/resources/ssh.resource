*** Settings ***
Documentation     SSH helpers for end-to-end tests against a real device.
...               Configure with environment variables (never commit their values):
...                 RP_E2E_HOST        user@host of the device (required)
...                 RP_E2E_PASSWORD    SSH password (omit to use your SSH key / agent)
...                 RP_E2E_SUDO_PASSWORD  sudo password if sudo is not passwordless
Library           SSHLibrary    timeout=60s
Resource          common.resource

*** Variables ***
${E2E_HOST}       %{RP_E2E_HOST=}
${E2E_PASSWORD}   %{RP_E2E_PASSWORD=}
${SUDO_PASSWORD}  %{RP_E2E_SUDO_PASSWORD=}

*** Keywords ***
Open Device Connection
    Skip If    '${E2E_HOST}' == ''    set RP_E2E_HOST=user@device to run end-to-end tests
    ${user}    ${host}=    Evaluate    $E2E_HOST.split('@', 1)
    Open Connection    ${host}    alias=device
    IF    '${E2E_PASSWORD}' != ''
        Login    ${user}    ${E2E_PASSWORD}
    ELSE
        Login With Public Key    ${user}    %{HOME}/.ssh/id_ed25519
    END

On Device
    [Documentation]    Run a command on the device; assert the exit code; return stdout.
    [Arguments]    ${command}    ${rc}=0
    ${out}    ${err}    ${code}=    Execute Command    ${command}
    ...    return_stdout=True    return_stderr=True    return_rc=True
    Log    ${out}\n${err}
    Should Be Equal As Integers    ${code}    ${rc}    msg=`${command}` -> ${code}: ${out}\n${err}
    RETURN    ${out}

As Root On Device
    [Documentation]    Run a shell command as root. The command is base64-encoded so no quoting
    ...                can break it; SSH_CONNECTION is passed through sudo for lockout checks.
    [Arguments]    ${command}    ${rc}=0
    ${b64}=    Evaluate    base64.b64encode($command.encode()).decode()    modules=base64
    ${run}=    Set Variable    env SSH_CONNECTION="$SSH_CONNECTION" sh -c 'echo ${b64} | base64 -d | sh'
    IF    '${SUDO_PASSWORD}' == ''
        ${out}=    On Device    sudo -n ${run}    ${rc}
    ELSE
        ${pw}=    Evaluate    base64.b64encode($SUDO_PASSWORD.encode()).decode()    modules=base64
        ${out}=    On Device    echo ${pw} | base64 -d | sudo -S -p '' ${run}    ${rc}
    END
    RETURN    ${out}

Write Root File On Device
    [Arguments]    ${path}    ${content}
    ${b64}=    Evaluate    base64.b64encode($content.encode()).decode()    modules=base64
    As Root On Device    echo ${b64} | base64 -d > ${path}
