*** Settings ***
Documentation     Static analysis: formatting, lints, shell/PowerShell analysis, secret scan.
Resource          ../resources/common.resource
Test Tags         static

*** Test Cases ***
Rust Code Is Formatted
    Run Ok    cargo    fmt    --all    --check

Clippy Reports No Warnings
    Run Ok    cargo    clippy    --workspace    --all-targets    --    -D    warnings

Shell Scripts Pass ShellCheck
    Require Tool    shellcheck
    @{scripts}=    List Files In Directory    ${REPO}/scripts    *.sh    absolute=True
    Run Ok    shellcheck    -x    ${INSTALL_SH}    ${REPO}/test/run.sh    @{scripts}

PowerShell Installer Passes PSScriptAnalyzer
    Require Tool    pwsh
    ${cmd}=    Catenate    SEPARATOR=${SPACE}
    ...    if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -RequiredVersion 1.23.0 };
    ...    $r = Invoke-ScriptAnalyzer -Path '${INSTALL_PS1}' -Severity Warning,Error -ExcludeRule PSAvoidUsingWriteHost;
    ...    $r | Format-Table -AutoSize | Out-String | Write-Output; exit $r.Count
    Run Ok    pwsh    -NoProfile    -NonInteractive    -Command    ${cmd}

Repository Contains No Secrets Or Real Network Identifiers
    [Documentation]    Fails on values from local.env, credential formats, LAN host IPs or real MACs.
    ${out}=    Run Ok    ${PROBE}    secret-scan    --env-file    ${REPO}/local.env    ${REPO}
    Should Contain    ${out}    findings: 0

Every Managed File Carries The Ownership Header
    @{files}=    List Files Recursively    ${FIXTURES}/golden
    Should Not Be Empty    ${files}
    FOR    ${f}    IN    @{files}
        ${t}=    Get File    ${FIXTURES}/golden/${f}
        Should Contain    ${t}    Managed by rpctl
    END
