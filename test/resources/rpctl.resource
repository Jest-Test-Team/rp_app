*** Settings ***
Documentation     Keywords for driving rpctl against a fake filesystem root.
...               Commands are recorded (never executed) via the hidden
...               --record-commands test mode, so no root privileges are needed.
Resource          common.resource

*** Keywords ***
Create Fake Root
    [Documentation]    A minimal Debian-like root with eth0 up and the binaries preflight looks for.
    [Arguments]    ${carrier}=1
    ${root}=    New Temp Dir
    FOR    ${b}    IN    nft    systemctl    sshd    sysctl    ip
        Create File    ${root}/usr/sbin/${b}
    END
    Create File    ${root}/sys/class/net/eth0/carrier    ${carrier}\n
    Create File    ${root}/sys/class/net/wlan0/carrier    1\n
    Create File    ${root}/etc/os-release    ID=debian\n
    RETURN    ${root}

Rpctl
    [Documentation]    Run rpctl on ${root} as a simulated root user and assert the exit code.
    [Arguments]    ${root}    ${expected_rc}    @{args}    ${config}=${FIXTURES}/config/basic.toml
    ...    ${fail}=${EMPTY}    &{opts}
    ${r}=    Run Expecting    ${expected_rc}    ${RPCTL}
    ...    --config    ${config}    --root    ${root}
    ...    --record-commands    ${root}/cmds.log
    ...    --fake-output    id -u\=0
    ...    --fake-output    dpkg-query\=install ok installed
    ...    --fake-output    nmcli -g WIFI-PROPERTIES.AP\=yes
    ...    --fail-commands    ${fail}
    ...    @{args}    &{opts}
    RETURN    ${r.stdout}

Recorded Commands
    [Arguments]    ${root}
    ${exists}=    Run Keyword And Return Status    File Should Exist    ${root}/cmds.log
    IF    not ${exists}    RETURN    @{EMPTY}
    ${text}=    Get File    ${root}/cmds.log
    @{lines}=    Split To Lines    ${text}
    RETURN    @{lines}

Index Of Command
    [Documentation]    Index of the first recorded command starting with ${prefix}; fails if absent.
    [Arguments]    ${root}    ${prefix}
    @{cmds}=    Recorded Commands    ${root}
    FOR    ${i}    ${c}    IN ENUMERATE    @{cmds}
        IF    $c.startswith($prefix)    RETURN    ${i}
    END
    Fail    no recorded command starts with '${prefix}': ${cmds}

Managed Files Should Not Exist
    [Arguments]    ${root}
    FOR    ${p}    IN    etc/rp/nftables.nft    etc/systemd/system/rp-firewall.service
    ...    etc/sysctl.d/90-rp-base.conf    etc/ssh/sshd_config.d/10-rp.conf
        File Should Not Exist    ${root}/${p}
    END
