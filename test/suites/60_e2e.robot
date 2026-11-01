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
${ALLOW_IN_USE}   %{RP_E2E_ALLOW_IN_USE=0}
${IN_USE}         ${False}
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
    Should Match Regexp    ${out}    dry run:|already up to date
    ${after}=    As Root On Device    nft list ruleset | sha256sum
    Should Be Equal    ${before}    ${after}
    IF    not ${IN_USE}    As Root On Device    test ! -e /etc/rp/nftables.nft

Applied Modules Are Running (Device In Use)
    [Documentation]    Only meaningful against a configured device (RP_E2E_ALLOW_IN_USE=1).
    Skip If    not ${IN_USE}    fresh device: nothing applied yet
    ${s}=    As Root On Device    rpctl --config ${CFG} status
    FOR    ${line}    IN    @{{ [l for l in $s.splitlines() if 'applied=true' in l] }}
        Should Contain    ${line}    confirmed=true
    END
    As Root On Device    systemctl is-active --quiet rp-firewall
    As Root On Device    nft list chain inet rp input | grep -q 'policy drop'
    As Root On Device    rpctl audit verify

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

WireGuard Exit Node Applies Forwards And Rolls Back Cleanly
    [Tags]    destructive    vpn
    Require Apply
    As Root On Device    rpctl --config ${CFG} apply base --no-packages && rpctl confirm
    ${vpn}=    Catenate    SEPARATOR=\n
    ...    [vpn]
    ...    mode = "wireguard"
    ...    [vpn.wireguard]
    ...    endpoint = "vpn.example.invalid:51820"
    As Root On Device    cp ${CFG} ${CFG}.e2e-orig
    ${b64}=    Evaluate    base64.b64encode(('\n' + $vpn + '\n').encode()).decode()    modules=base64
    As Root On Device    echo ${b64} | base64 -d >> ${CFG}
    FOR    ${round}    IN RANGE    2
        As Root On Device    rpctl --config ${CFG} apply vpn && rpctl confirm
        As Root On Device    ip link show wg0
        ${fwd}=    As Root On Device    sysctl -n net.ipv4.ip_forward
        Should Be Equal    ${fwd}    1
        ${rules}=    As Root On Device    nft list table inet rp
        Should Contain    ${rules}    vpn_block4
        As Root On Device    test -s /etc/rp/wireguard/private.key && test "$(stat -c %a /etc/rp/wireguard/private.key)" = 600
        As Root On Device    rpctl --config ${CFG} rollback vpn
        ${off}=    As Root On Device    sysctl -n net.ipv4.ip_forward
        Should Be Equal    ${off}    0
        As Root On Device    ip link show wg0    rc=1
    END
    As Root On Device    mv ${CFG}.e2e-orig ${CFG} && rpctl --config ${CFG} rollback base

*** Keywords ***
Require Apply
    Skip If    '${APPLY}' != '1'    set RP_E2E_APPLY=1 to run state-changing tests
    Skip If    ${IN_USE}    refusing state-changing tests on a device that is in use

Prepare Device
    Open Device Connection
    # Never install over / tear down a configured device: teardown purges /etc/rp.
    ${rc}=    Execute Command    test -e /etc/rp/rp.toml    return_stdout=False    return_rc=True
    IF    ${rc} == 0
        Skip If    '${ALLOW_IN_USE}' != '1'
        ...    device already has /etc/rp/rp.toml (in use); set RP_E2E_ALLOW_IN_USE=1 for read-only checks
        Set Suite Variable    ${IN_USE}    ${True}
        RETURN
    END
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
    IF    ${IN_USE}
        Close All Connections
        RETURN
    END
    Run Keyword And Ignore Error    As Root On Device    rpctl --config ${CFG} rollback vpn
    Run Keyword And Ignore Error    As Root On Device    rpctl --config ${CFG} rollback base
    Run Keyword And Ignore Error    As Root On Device    bash ${REMOTE}/install.sh --uninstall --purge
    Run Keyword And Ignore Error    On Device    rm -rf ${REMOTE}
    Close All Connections
