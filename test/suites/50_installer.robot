*** Settings ***
Documentation     install.sh / install.ps1: argument validation, dry runs, packaging,
...               SHA256-verified release install from a local mirror, tamper detection,
...               uninstall and purge. Nothing touches the real system: --root is used.
...               PowerShell installer cases live in 51_installer_ps1.robot.
Resource          ../resources/common.resource
Suite Setup       Build Release Mirror
Test Tags         installer

*** Variables ***
${TRIPLE}         ${EMPTY}
${MIRROR}         ${EMPTY}
${ASSET}          ${EMPTY}

*** Test Cases ***
Help Describes All Install Sources
    ${out}=    Run Ok    bash    ${INSTALL_SH}    --help
    Should Contain    ${out}    --release
    Should Contain    ${out}    --from-source
    Should Contain    ${out}    --archive

Malicious Arguments Are Rejected
    [Template]    Installer Rejects
    --repo       evil;rm -rf /      invalid --repo
    --release    v1;reboot          invalid release tag
    --prefix     /x$(id)            invalid --prefix
    --host       a@b;id             invalid --host
    --bogus      x                  unknown option

Unknown Target Triples Are Refused
    [Template]    Installer Rejects
    --target    armv6l                            unsupported target
    --target    x86_64-unknown-linux-gnu;id       unsupported target

Local Dry Run Prints The Plan And Changes Nothing
    ${root}=    New Temp Dir
    ${out}=    Run Ok    bash    ${INSTALL_SH}    --dry-run    --target    ${TRIPLE}    --root    ${root}
    Should Contain    ${out}    would: download https://github.com/Jest-Test-Team/rp_app/releases/latest/download/rp-${TRIPLE}.tar.gz
    Should Contain    ${out}    would: verify against
    Directory Should Be Empty    ${root}

Remote Dry Run Uses A Pinned Tag And Never Connects
    ${out}=    Run Ok    bash    ${INSTALL_SH}    --dry-run    --host    pi@example.invalid
    ...    --target    armv7-unknown-linux-gnueabihf    --release    v0.1.0
    Should Contain    ${out}    releases/download/v0.1.0/rp-armv7-unknown-linux-gnueabihf.tar.gz
    Should Contain    ${out}    would: ssh pi@example.invalid sudo bash /tmp/install.sh --archive

Release Install Verifies Checksum And Lays Out Files
    ${root}=    New Temp Dir
    ${out}=    Run Ok    bash    ${INSTALL_SH}    --base-url    file://${MIRROR}    --target    ${TRIPLE}
    ...    --root    ${root}
    Should Contain    ${out}    checksum OK
    File Should Exist    ${root}/usr/local/bin/rpctl
    File Should Exist    ${root}/etc/rp/rp.toml
    File Should Exist    ${root}/etc/rp/rp.example.toml
    File Should Exist    ${root}/var/lib/rp/install-manifest.txt
    ${mode}=    Evaluate    oct(os.stat($root + '/usr/local/bin/rpctl').st_mode & 0o777)    modules=os
    Should Be Equal    ${mode}    0o755

Existing Config Is Never Overwritten
    ${root}=    New Temp Dir
    Create File    ${root}/etc/rp/rp.toml    \# my edited config\n
    ${out}=    Run Ok    bash    ${INSTALL_SH}    --base-url    file://${MIRROR}    --target    ${TRIPLE}
    ...    --root    ${root}
    Should Contain    ${out}    kept existing
    ${cfg}=    Get File    ${root}/etc/rp/rp.toml
    Should Be Equal    ${cfg}    \# my edited config\n

Tampered Archive Is Refused
    ${bad}=    New Temp Dir
    Copy Directory    ${MIRROR}/latest    ${bad}/latest
    Create File    ${bad}/latest/SHA256SUMS    ${{ '0' * 64 }}${SPACE}${SPACE}${ASSET}\n
    ${root}=    New Temp Dir
    ${r}=    Run Expecting    1    bash    ${INSTALL_SH}    --base-url    file://${bad}    --target    ${TRIPLE}
    ...    --root    ${root}
    Should Contain    ${r.stdout}    checksum mismatch
    Directory Should Be Empty    ${root}

Archive Missing From SHA256SUMS Is Refused
    ${bad}=    New Temp Dir
    Copy Directory    ${MIRROR}/latest    ${bad}/latest
    Create File    ${bad}/latest/SHA256SUMS    ${{ 'a' * 64 }}${SPACE}${SPACE}some-other-file.tar.gz\n
    ${r}=    Run Expecting    1    bash    ${INSTALL_SH}    --base-url    file://${bad}    --target    ${TRIPLE}
    ...    --root    ${EXECDIR}/never-created
    Should Contain    ${r.stdout}    is not listed in SHA256SUMS

Uninstall Keeps Config And Purge Removes Everything
    ${root}=    New Temp Dir
    Run Ok    bash    ${INSTALL_SH}    --base-url    file://${MIRROR}    --target    ${TRIPLE}    --root    ${root}
    ${out}=    Run Ok    bash    ${INSTALL_SH}    --uninstall    --root    ${root}
    Should Contain    ${out}    config in /etc/rp kept
    File Should Not Exist    ${root}/usr/local/bin/rpctl
    File Should Exist    ${root}/etc/rp/rp.toml
    Run Ok    bash    ${INSTALL_SH}    --uninstall    --purge    --root    ${root}
    Directory Should Not Exist    ${root}/etc/rp
    Directory Should Not Exist    ${root}/var/lib/rp

Installed Binary Runs
    [Documentation]    Only meaningful when the packaged target matches this machine.
    ${linux}=    Is Linux
    Skip If    not ${linux}    packaged binary targets Linux
    ${root}=    New Temp Dir
    Run Ok    bash    ${INSTALL_SH}    --base-url    file://${MIRROR}    --target    ${TRIPLE}    --root    ${root}
    ${v}=    Run Ok    ${root}/usr/local/bin/rpctl    --version
    Should Start With    ${v}    rpctl

*** Keywords ***
Build Release Mirror
    [Documentation]    Package the current tree with install.sh --package-only and lay it
    ...                out like a GitHub release (latest/ + SHA256SUMS) under a temp dir.
    ${native}=    Native Linux Triple
    ${linux}=    Is Linux
    ${triple}=    Set Variable If    ${linux} and '${native}' != 'None'    ${native}
    ...    armv7-unknown-linux-gnueabihf
    ${mirror}=    New Temp Dir
    ${r}=    Run Expecting    0    bash    ${INSTALL_SH}    --package-only    ${mirror}/latest
    ...    --target    ${triple}
    ${asset}=    Set Variable    rp-${triple}.tar.gz
    File Should Exist    ${mirror}/latest/${asset}
    ${sum}=    Evaluate    hashlib.sha256(open($mirror + '/latest/' + $asset, 'rb').read()).hexdigest()
    ...    modules=hashlib
    Create File    ${mirror}/latest/SHA256SUMS    ${sum}${SPACE}${SPACE}${asset}\n
    Set Suite Variable    ${TRIPLE}    ${triple}
    Set Suite Variable    ${MIRROR}    ${mirror}
    Set Suite Variable    ${ASSET}    ${asset}

Installer Rejects
    [Arguments]    ${flag}    ${value}    ${message}
    ${r}=    Run Expecting    1    bash    ${INSTALL_SH}    --dry-run    ${flag}    ${value}
    Should Contain    ${r.stdout}    ${message}
