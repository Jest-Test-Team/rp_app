*** Settings ***
Documentation     install.ps1 (Windows deploy over OpenSSH): dry-run plan and parameter
...               validation. Needs only pwsh — no Rust build — so it runs on Windows CI.
Resource          ../resources/common.resource
Test Tags         installer    pwsh

*** Test Cases ***
PowerShell Dry Run Prints The Plan
    Require Tool    pwsh
    ${out}=    Run Ok    pwsh    -NoProfile    -NonInteractive    -File    ${INSTALL_PS1}
    ...    -Target    pi@example.invalid    -Triple    armv7-unknown-linux-gnueabihf
    ...    -Version    v0.1.0    -DryRun
    Should Contain    ${out}    releases/download/v0.1.0/rp-armv7-unknown-linux-gnueabihf.tar.gz
    Should Contain    ${out}    would: ssh pi@example.invalid sudo bash /tmp/install.sh

PowerShell Rejects Malicious Arguments
    [Template]    PowerShell Rejects
    -Version    v1;reboot
    -Repo       evil;rm
    -Prefix     /x$(id)
    -Target     a@b;id

*** Keywords ***
PowerShell Rejects
    [Arguments]    ${param}    ${value}
    Require Tool    pwsh
    @{target}=    IF    '${param}' == '-Target'    Create List
    ...    ELSE    Create List    -Target    pi@example.invalid
    ${r}=    Run Process    pwsh    -NoProfile    -NonInteractive    -File    ${INSTALL_PS1}
    ...    @{target}    -Triple    armv7-unknown-linux-gnueabihf    -DryRun
    ...    ${param}    ${value}    stderr=STDOUT
    Should Not Be Equal As Integers    ${r.rc}    0
    Should Contain Any    ${r.stdout}    ValidatePattern    does not match    Cannot validate
