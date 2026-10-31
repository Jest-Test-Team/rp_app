*** Settings ***
Documentation     End-to-end on a real device over SSH.
...
...               Tag `e2e`: installs the freshly built binaries with install.sh (archive mode),
...               then runs check / preflight / dry-run. Teardown uninstalls. Low risk.
...
...               Tag `destructive` (also needs RP_E2E_APPLY=1): really applies the firewall
...               and VPN modules, exercises confirm, the dead-man rollback and rollback.
...               Only run with a working wired management connection.
Resource          ../resources/ssh.resource
Suite Setup       Prepare Device
Suite Teardown    Clean Up Device
Test Tags         e2e    requires-pi

*** Variables ***
${TRIPLE}         armv7-unknown-linux-gnueabihf
${REMOTE}         /tmp/rp-e2e
${APPLY}          %{RP_E2E_APPLY=0}
${CFG}            /etc/rp/rp.toml

*** Test Cases ***
Device Is A Supported Raspberry Pi
    ${model}=    On Device    tr -d '\\0' < /proc/device-tree/model
    Should Contain    ${model}    Raspberry Pi
    ${arch}=    On Device    uname -m
    Should Be Equal    ${arch}    armv7l

Kernel Provides WireGuard, nftables And NAT
    FOR    ${m}    IN    wireguard    nf_tables    nft_masq    nft_chain_nat
        On Device    find /lib/modules/$(uname -r) -name '${m}.ko*' | grep -q .
    END

Installed rpctl Runs Natively
    ${v}=    On Device    rpctl --version
    Should Start With    ${v}    rpctl

Generated Config Validates On The Device
    As Root On Device    rpctl --config ${CFG} check

Preflight Passes For Base Over The Current Session
    ${out}=    As Root On Device    rpctl --config ${CFG} preflight base
    Should Contain    ${out}    current SSH session is inside ssh allow-list

Dry Run Changes Nothing On The Device
    ${before}=    As Root On Device    nft list ruleset | sha256sum
    ${out}=    As Root On Device    rpctl --config ${CFG} apply base --dry-run
    Should Contain    ${out}    dry run:
    ${after}=    As Root On Device    nft list ruleset | sha256sum
    Should Be Equal    ${before}    ${after}
    As Root On Device    test ! -e /etc/rp/nftables.nft

Apply Confirm And Rollback Base Keeps SSH Working
    [Tags]    destructive
    Require Apply
    As Root On Device    rpctl --config ${CFG} apply base --no-packages
    # A fresh connection must still work before we confirm.
    Close All Connections
    Open Device Connection
    As Root On Device    rpctl confirm
    ${s}=    As Root On Device    rpctl --config ${CFG} status
    Should Contain    ${s}    applied=true confirmed=true
    ${rules}=    As Root On Device    nft list table inet rp
    Should Contain    ${rules}    policy drop
    As Root On Device    rpctl --config ${CFG} rollback base
    As Root On Device    nft list table inet rp    rc=1

Unconfirmed Firewall Change Rolls Back Automatically
    [Tags]    destructive
    Require Apply
    As Root On Device    sed -i 's/^confirm_timeout_secs.*/confirm_timeout_secs = 30/' ${CFG} || true
    As Root On Device    rpctl --config ${CFG} apply base --no-packages
    Sleep    45s
    ${s}=    As Root On Device    rpctl --config ${CFG} status
    Should Contain    ${s}    applied=false
    As Root On Device    nft list table inet rp    rc=1

*** Keywords ***
Require Apply
    Skip If    '${APPLY}' != '1'    set RP_E2E_APPLY=1 to run state-changing tests

Prepare Device
    Open Device Connection
    ${pkg}=    New Temp Dir
    Run Ok    bash    ${INSTALL_SH}    --package-only    ${pkg}    --target    ${TRIPLE}
    On Device    rm -rf ${REMOTE} && mkdir -p ${REMOTE}
    Put File    ${pkg}/rp-${TRIPLE}.tar.gz    ${REMOTE}/
    Put File    ${INSTALL_SH}    ${REMOTE}/
    As Root On Device    bash ${REMOTE}/install.sh --archive ${REMOTE}/rp-${TRIPLE}.tar.gz
    # Configure for the device's real management interface and LAN, detected on-device.
    ${iface}=    On Device    ip route show default | awk '{print $5; exit}'
    ${cidr}=    On Device    ip -4 -o addr show dev ${iface} | awk '{print $4; exit}' | python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.stdin.read().strip()).network)'
    ${toml}=    Catenate    SEPARATOR=\n
    ...    [device]
    ...    wan_if = "${iface}"
    ...    lan_cidrs = ["${cidr}"]
    ...    [base]
    ...    unattended_upgrades = false
    Write Root File On Device    ${CFG}    ${toml}\n
    Set Suite Variable    ${E2E_IFACE}    ${iface}

Clean Up Device
    Run Keyword And Ignore Error    As Root On Device    rpctl --config ${CFG} rollback vpn
    Run Keyword And Ignore Error    As Root On Device    rpctl --config ${CFG} rollback base
    Run Keyword And Ignore Error    As Root On Device    bash ${REMOTE}/install.sh --uninstall --purge
    Run Keyword And Ignore Error    On Device    rm -rf ${REMOTE}
    Close All Connections
