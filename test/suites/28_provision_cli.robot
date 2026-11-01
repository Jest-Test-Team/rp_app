*** Settings ***
Documentation     First-boot provisioning (path A) and `rpctl init`: files written onto a
...               flashed boot partition, the pairing secret kept out of user-data, inputs
...               validated, Wi-Fi password never printed; config detection for the network.
Resource          ../resources/rpctl.resource
Test Tags         cli    provision

*** Variables ***
${PV}             ${FIXTURES}/provision
${SHA}            cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

*** Test Cases ***
Render Matches The Golden Files Shared With The App
    FOR    ${name}    IN    minimal    full
        ${out}=    Run Ok    ${RPCTL}    bootfs    render    --spec    ${PV}/${name}.spec.json
        ${got}=    Evaluate    json.loads($out)    modules=json
        ${want}=    Evaluate    json.load(open('${PV}/${name}.files.json'))    modules=json
        Should Be Equal    ${got}    ${want}
    END

Write Prepares A Flashed Card And Prints A Pairing Code
    ${boot}=    Flashed Boot Partition
    ${out}=    Run Ok    ${RPCTL}    --json    bootfs    write    --dir    ${boot}    --tag    v0.2.0
    ...    --install-sha256    ${SHA}    --hostname    rp-test
    ${qr}=    Evaluate    json.loads($out)    modules=json
    Should Be Equal    ${qr['host']}    rp-test.local
    Length Should Be    ${qr['secret']}    64
    ${ud}=    Get File    ${boot}/user-data
    Should Start With    ${ud}    \#cloud-config
    Should Not Contain    ${ud}    ${qr['secret']}
    Should Contain    ${ud}    ${SHA}
    ${pair}=    Get File    ${boot}/rp-pairing.toml
    Should Contain    ${pair}    ${qr['secret']}
    ${meta}=    Get File    ${boot}/meta-data
    Should Match Regexp    ${meta}    instance_id: rp-\\d+
    Should Not Contain    ${meta}    rpios-old
    File Should Not Exist    ${boot}/network-config

Two Cards Get Different Secrets
    ${a}=    Flashed Boot Partition
    ${b}=    Flashed Boot Partition
    ${x}=    Run Ok    ${RPCTL}    --json    bootfs    write    --dir    ${a}    --tag    v0.2.0    --install-sha256    ${SHA}
    ${y}=    Run Ok    ${RPCTL}    --json    bootfs    write    --dir    ${b}    --tag    v0.2.0    --install-sha256    ${SHA}
    Should Not Be Equal    ${x}    ${y}

Wi-Fi Password Comes From Stdin And Is Never Printed
    ${boot}=    Flashed Boot Partition
    ${r}=    Run Expecting    0    ${RPCTL}    bootfs    write    --dir    ${boot}    --tag    v0.2.0
    ...    --install-sha256    ${SHA}    --wifi-ssid    Example Net    --wifi-country    tw    --no-qr
    ...    stdin=very secret pass
    Should Not Contain    ${r.stdout}    very secret pass
    ${nc}=    Get File    ${boot}/network-config
    Should Contain    ${nc}    password: "very secret pass"
    Should Contain    ${nc}    regulatory-domain: "TW"

Admin Account Is Key Only
    ${boot}=    Flashed Boot Partition
    Create File    ${boot}/../key.pub    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnlyForTests robot@example\n
    Run Ok    ${RPCTL}    bootfs    write    --dir    ${boot}    --tag    v0.2.0    --install-sha256    ${SHA}
    ...    --admin-user    admin    --ssh-key-file    ${boot}/../key.pub    --no-qr
    ${ud}=    Get File    ${boot}/user-data
    Should Contain    ${ud}    lock_passwd: true
    Should Contain    ${ud}    ssh_pwauth: false
    Should Contain    ${ud}    robot@example

Bad Input And Non Boot Partitions Are Refused
    ${boot}=    Flashed Boot Partition
    ${r}=    Run Expecting    1    ${RPCTL}    bootfs    write    --dir    ${boot}    --tag    main;reboot
    ...    --install-sha256    ${SHA}
    Should Contain    ${r.stdout}    tag
    ${r}=    Run Expecting    1    ${RPCTL}    bootfs    write    --dir    ${boot}    --tag    v0.2.0
    ...    --install-sha256    nothex
    Should Contain    ${r.stdout}    install_sha256
    ${r}=    Run Expecting    1    ${RPCTL}    bootfs    write    --dir    ${boot}    --tag    v0.2.0
    ...    --install-sha256    ${SHA}    --hostname    bad host
    Should Contain    ${r.stdout}    hostname
    ${plain}=    New Temp Dir
    ${r}=    Run Expecting    1    ${RPCTL}    bootfs    write    --dir    ${plain}    --tag    v0.2.0
    ...    --install-sha256    ${SHA}
    Should Contain    ${r.stdout}    not a freshly flashed
    File Should Not Exist    ${plain}/user-data

Init Writes A Valid Config For The Detected Network
    ${root}=    Create Fake Root
    ${cfg}=    Set Variable    ${root}/etc/rp/rp.toml
    ${r}=    Run Expecting    0    ${RPCTL}    --config    ${cfg}    --root    ${root}
    ...    --record-commands    ${root}/cmds.log
    ...    --fake-output    ip -j route show default\=[{"dev":"eth0","gateway":"192.0.2.1"}]
    ...    --fake-output    ip -j addr show dev eth0\=[{"addr_info":[{"local":"192.0.2.10","prefixlen":24}]}]
    ...    init    --auto
    Should Contain    ${r.stdout}    uplink eth0, LAN 192.0.2.0/24
    Run Ok    ${RPCTL}    --config    ${cfg}    check
    ${again}=    Run Ok    ${RPCTL}    --config    ${cfg}    --root    ${root}    init    --auto
    Should Contain    ${again}    nothing to do

Init Without A Network Explains Why
    ${root}=    Create Fake Root
    ${r}=    Run Expecting    1    ${RPCTL}    --config    ${root}/rp.toml    --root    ${root}
    ...    --record-commands    ${root}/cmds.log    --fake-output    ip -j route show default\=[]
    ...    init    --auto
    Should Contain    ${r.stdout}    no default route
    File Should Not Exist    ${root}/rp.toml

Setup On A Fresh Device Writes A Config Applies And Opens Pairing
    ${root}=    Create Fake Root
    Create File    ${root}/sys/class/net/eth0/device/vendor    x
    Create File    ${root}/etc/hostname    rp-test\n
    ${cfg}=    Set Variable    ${root}/etc/rp/rp.toml
    ${out}=    Setup    ${root}    ${cfg}    0
    ${r}=    Evaluate    json.loads($out.splitlines()[-1])    modules=json
    Should Be True    ${r['config_written']}
    Should Be Equal    ${r['applied']['api']}    ${5}    msg=5 installed files (the nft check file is staging-only)
    Should Be Equal    ${r['pairing']['host']}    rp-test.local
    Length Should Be    ${r['pairing']['secret']}    64
    ${cmds}=    Get File    ${root}/cmds.log
    Should Contain    ${cmds}    systemctl enable --now rp-privd.socket
    Should Contain    ${cmds}    systemctl restart rp-api.service
    Should Not Contain    ${cmds}    rp-confirm-    msg=setup runs no confirm timers
    # Idempotent: nothing more to apply, pairing already open.
    ${out}=    Setup    ${root}    ${cfg}    0
    ${r}=    Evaluate    json.loads($out.splitlines()[-1])    modules=json
    Should Not Be True    ${r['config_written']}
    Should Be Equal    ${r['applied']}    ${{ {'base': 0, 'agent': 0, 'api': 0} }}
    Should Be Equal    ${r['pairing']}    ${None}

Setup Upgrades A v0.1 Config Without Touching The Rest
    ${root}=    Create Fake Root
    Create File    ${root}/sys/class/net/eth0/device/vendor    x
    ${cfg}=    Set Variable    ${root}/rp.toml
    Copy File    ${FIXTURES}/config/dns.toml    ${cfg}
    ${before}=    Get File    ${cfg}
    ${out}=    Setup    ${root}    ${cfg}    0
    ${r}=    Evaluate    json.loads($out.splitlines()[-1])    modules=json
    Should Be Equal    ${r['sections_added']}    ${{ ['agent', 'api'] }}
    ${after}=    Get File    ${cfg}
    Should Start With    ${after}    ${before.rstrip()}
    @{bak}=    List Files In Directory    ${root}    rp.toml.bak-*
    Length Should Be    ${bak}    1

Setup Stops At A Failed Preflight And Changes Nothing Else
    ${root}=    Create Fake Root    carrier=0
    ${cfg}=    Set Variable    ${root}/rp.toml
    Copy File    ${FIXTURES}/config/basic.toml    ${cfg}
    ${out}=    Setup    ${root}    ${cfg}    2
    Should Contain    ${out}    "failed_module":"base"
    File Should Not Exist    ${root}/etc/rp/nftables.nft
    File Should Not Exist    ${root}/etc/rp/pairing.toml

*** Keywords ***
Setup
    [Arguments]    ${root}    ${cfg}    ${rc}
    ${r}=    Run Expecting    ${rc}    ${RPCTL}    --json    --config    ${cfg}    --root    ${root}
    ...    --record-commands    ${root}/cmds.log
    ...    --fake-output    id -u\=0    --fake-output    dpkg-query\=install ok installed
    ...    --fake-output    uname -m\=armv7l
    ...    --fake-output    ip -j route show default\=[{"dev":"eth0"}]
    ...    --fake-output    ip -j addr show dev eth0\=[{"addr_info":[{"local":"192.0.2.10","prefixlen":24}]}]
    ...    setup    --no-packages
    RETURN    ${r.stdout}

Flashed Boot Partition
    ${d}=    New Temp Dir
    Create File    ${d}/boot/cmdline.txt    console=serial0,115200 root=PARTUUID=x rootfstype=ext4
    Create File    ${d}/boot/meta-data    dsmode: local\ninstance_id: rpios-old\n
    RETURN    ${d}/boot
