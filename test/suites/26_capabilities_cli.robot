*** Settings ***
Documentation     `rpctl capabilities`: per-module availability with stable reason codes for
...               every hardware shape the console must handle (fixtures in fixtures/capabilities).
Resource          ../resources/rpctl.resource
Test Tags         cli    capabilities

*** Variables ***
${CAPS}           ${FIXTURES}/capabilities

*** Test Cases ***
Pi 2B With Ethernet And An AP Adapter Can Run Every Module
    ${c}=    Capabilities For    pi2b-eth-wifi
    Should Be True    ${c['device']['supported']}
    FOR    ${m}    IN    base    vpn    dns    ap    agent    firewall    api
        Should Be True    ${c['modules']['${m}']['available']}    msg=${m} should be available
    END
    Should Be Equal    ${c['modules']['ap']['options']}    ${{ ['wlan0'] }}
    Should Be Equal    ${c['modules']['ap']['notes']}    ${{ ['wpa2_only'] }}
    Should Be Equal    ${c['modules']['vpn']['options']}    ${{ ['tailscale', 'wireguard'] }}

No Wi-Fi Disables Only The Access Point
    ${c}=    Capabilities For    no-wifi
    Should Be Equal    ${c['modules']['ap']['reasons']}    ${{ ['no_wifi_interface'] }}
    Should Be True    ${c['modules']['vpn']['available']} and ${c['modules']['dns']['available']}

Turning The Management Wi-Fi Into An AP Is Refused
    ${c}=    Capabilities For    wifi-is-mgmt
    Should Contain    ${c['modules']['ap']['reasons']}    would_drop_management_link
    Should Contain    ${c['modules']['ap']['reasons']}    no_wired_uplink
    Should Be True    ${c['interfaces'][0]['is_mgmt']}

Unplugged Ethernet Blocks The AP But Not The VPN
    ${c}=    Capabilities For    eth-unplugged
    Should Contain    ${c['modules']['ap']['reasons']}    no_wired_uplink
    Should Be True    ${c['modules']['vpn']['available']}

ARMv6 Boards Are Unsupported
    ${c}=    Capabilities For    armv6
    Should Not Be True    ${c['device']['supported']}
    FOR    ${name}    ${m}    IN    &{c['modules']}
        Should Contain    ${m['reasons']}    unsupported_arch
    END

WPA3 Capable Dual Band Adapter Has No WPA2 Note
    ${c}=    Capabilities For    pi4-wpa3
    Should Be Empty    ${c['modules']['ap']['notes']}
    Should Be Equal    ${c['interfaces'][1]['bands']}    ${{ ['2.4', '5'] }}

Live Detection On A Fake Root Uses The Route To The Management Peer
    ${root}=    New Temp Dir
    Create File    ${root}/proc/device-tree/model    Raspberry Pi 3 Model B Rev 1.2
    Create File    ${root}/sys/class/net/eth0/carrier    1\n
    Create File    ${root}/sys/class/net/eth0/device/vendor    x
    ${r}=    Run Expecting    0    ${RPCTL}    --root    ${root}    --config    ${root}/missing.toml
    ...    --record-commands    ${root}/cmds.log
    ...    --fake-output    uname -m\=aarch64
    ...    --fake-output    ip -j route get\=[{"dev":"eth0"}]
    ...    capabilities    --peer    192.0.2.50
    ${c}=    Evaluate    json.loads($r.stdout)    modules=json
    Should Be Equal    ${c['device']['model']}    Raspberry Pi 3 Model B Rev 1.2
    Should Be True    ${c['interfaces'][0]['is_mgmt']}
    Should Contain    ${c['modules']['ap']['reasons']}    no_wifi_interface
    ${cmds}=    Get File    ${root}/cmds.log
    Should Contain    ${cmds}    ip -j route get 192.0.2.50

Invalid Facts File Is An Error
    ${d}=    New Temp Dir
    Create File    ${d}/bad.json    {"model": 1}
    ${r}=    Run Expecting    1    ${RPCTL}    capabilities    --facts    ${d}/bad.json
    Should Contain    ${r.stdout}    invalid facts file

*** Keywords ***
Capabilities For
    [Arguments]    ${fixture}
    ${out}=    Run Ok    ${RPCTL}    capabilities    --facts    ${CAPS}/${fixture}.json
    ${c}=    Evaluate    json.loads($out)    modules=json
    RETURN    ${c}
