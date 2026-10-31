*** Settings ***
Documentation     Real access point on virtual radios (mac80211_hwsim): the hostapd and
...               dnsmasq configs rendered by rpctl are run for real in network namespaces,
...               with wpa_supplicant clients. Proves WPA2 auth (right/wrong passphrase),
...               DHCP from the configured pool, DHCP-only dnsmasq (no DNS on :53), and
...               ap_isolate. Never touches physical Wi-Fi. Skips if tools are missing.
Resource          ../resources/common.resource
Suite Setup       Start Virtual Radios
Suite Teardown    Stop Virtual Radios
Test Tags         integration    requires-root    ap    hwsim

*** Variables ***
${PASS}           hwsim test passphrase
${SSID}           rp-hwsim-test
${DIR}            ${EMPTY}
${P}              ${EMPTY}

*** Test Cases ***
Client With The Right Passphrase Associates
    Connect Client    c1    ${PASS}
    Wait Until Keyword Succeeds    20s    1s    Client Is Associated    c1

Client With A Wrong Passphrase Is Rejected
    Connect Client    c2    wrong passphrase here
    Sleep    8s
    ${state}=    Client State    c2
    Should Not Be Equal    ${state}    COMPLETED
    Disconnect Client    c2

Client Gets A DHCP Lease From The Configured Pool
    ${tool}=    DHCP Client Tool
    Run In    c1    @{tool}    wlan0    timeout=30s
    ${addr}=    Run In    c1    ip    -4    -o    addr    show    dev    wlan0
    Should Match Regexp    ${addr.stdout}    198\\.51\\.100\\.(1[3-9][0-9]|2[0-4][0-9])/
    ${ping}=    Run In    c1    ping    -c1    -W2    198.51.100.129
    Should Be Equal As Integers    ${ping.rc}    0

dnsmasq Does Not Serve DNS
    ${r}=    Run In    c1    python3    -c
    ...    import socket; s=socket.socket(); s.settimeout(3); print('open' if s.connect_ex(('198.51.100.129', 53)) == 0 else 'closed')
    Should Be Equal    ${r.stdout.strip()}    closed

Clients Cannot Reach Each Other Over The Air
    [Documentation]    ap_isolate=1: a second associated client is unreachable from the first.
    Connect Client    c2    ${PASS}
    Wait Until Keyword Succeeds    20s    1s    Client Is Associated    c2
    Run In    c2    ip    addr    add    198.51.100.200/25    dev    wlan0
    ${ping}=    Run In    c1    ping    -c2    -W2    198.51.100.200
    Should Not Be Equal As Integers    ${ping.rc}    0

*** Keywords ***
Run In
    [Arguments]    ${ns}    @{argv}    ${timeout}=20s
    ${r}=    Run Process    ip    netns    exec    ${P}${ns}    @{argv}    stderr=STDOUT    timeout=${timeout}
    Log    ${r.stdout}
    RETURN    ${r}

Require
    ${linux}=    Is Linux
    Skip If    not ${linux}    needs Linux
    ${uid}=    Evaluate    os.geteuid()    modules=os
    Skip If    ${uid} != 0    needs root
    FOR    ${t}    IN    hostapd    wpa_supplicant    wpa_cli    iw    dnsmasq    modprobe
        Require Tool    ${t}
    END
    ${m}=    Run Process    modprobe    mac80211_hwsim    radios\=3
    Skip If    ${m.rc} != 0    mac80211_hwsim not available: ${m.stderr}

DHCP Client Tool
    FOR    ${t}    ${args}    IN    dhclient    -1 -v    udhcpc    -n -q -i    dhcpcd    -1 -4
        ${p}=    Evaluate    shutil.which($t) or ''    modules=shutil
        IF    '${p}' != ''
            @{argv}=    Evaluate    [$t] + $args.split()
            RETURN    ${argv}
        END
    END
    Skip    no DHCP client (dhclient/udhcpc/dhcpcd) installed

Start Virtual Radios
    Require
    ${P}=    Evaluate    'rph' + __import__('secrets').token_hex(3) + '-'
    Set Suite Variable    ${P}
    ${DIR}=    New Temp Dir
    Set Suite Variable    ${DIR}
    # Radios whose driver is mac80211_hwsim (never a physical adapter).
    @{hw}=    Evaluate
    ...    sorted(p for p in os.listdir('/sys/class/ieee80211') if 'hwsim' in os.path.realpath('/sys/class/ieee80211/%s/device/driver' % p))
    ...    modules=os
    ${n}=    Get Length    ${hw}
    Skip If    ${n} < 3    expected 3 hwsim radios, found ${n}
    FOR    ${ns}    ${phy}    IN ZIP    ${{ ['ap', 'c1', 'c2'] }}    ${hw[-3:]}
        Run Process    ip    netns    add    ${P}${ns}
        Run Process    iw    phy    ${phy}    set    netns    name    ${P}${ns}
        ${dev}=    Run Process    ip    netns    exec    ${P}${ns}    sh    -c
        ...    ls /sys/class/net | grep -v '^lo$' | head -1
        Run In    ${ns}    ip    link    set    ${dev.stdout.strip()}    name    wlan0
        Run In    ${ns}    ip    link    set    lo    up
    END
    # Render the AP with rpctl and run it for real.
    ${toml}=    Catenate    SEPARATOR=\n
    ...    [device]
    ...    wan_if = "eth0"
    ...    lan_cidrs = ["192.0.2.0/24"]
    ...    [ap]
    ...    ssid = "${SSID}"
    ...    country = "TW"
    ...    subnet = "198.51.100.128/25"
    ...    passphrase_file = "${DIR}/ap.psk"
    Create File    ${DIR}/rp.toml    ${toml}\n
    ${set}=    Run Process    ${RPCTL}    --config    ${DIR}/rp.toml    ap    set-passphrase    --stdin
    ...    stdin=${PASS}\n
    Should Be Equal As Integers    ${set.rc}    0
    Run Ok    ${RPCTL}    --config    ${DIR}/rp.toml    render    ap    --out    ${DIR}/out
    ${dm}=    Get File    ${DIR}/out/etc/rp/ap/dnsmasq.conf
    ${dm}=    Replace String    ${dm}    /var/lib/rp/ap/dnsmasq.leases    ${DIR}/leases
    Create File    ${DIR}/dnsmasq.conf    ${dm}
    Run In    ap    ip    link    set    wlan0    up
    Run In    ap    ip    addr    add    198.51.100.129/25    dev    wlan0
    Start Process    ip    netns    exec    ${P}ap    hostapd    ${DIR}/out/etc/rp/ap/hostapd.conf
    ...    alias=hostapd    stdout=${DIR}/hostapd.log    stderr=STDOUT
    Sleep    3s
    Start Process    ip    netns    exec    ${P}ap    dnsmasq    --keep-in-foreground
    ...    --conf-file\=${DIR}/dnsmasq.conf    --pid-file\=${DIR}/dnsmasq.pid
    ...    alias=dnsmasq    stdout=${DIR}/dnsmasq.log    stderr=STDOUT

Connect Client
    [Arguments]    ${ns}    ${pass}
    ${conf}=    Catenate    SEPARATOR=\n
    ...    ctrl_interface=${DIR}/wpa-${ns}
    ...    network={
    ...    \ \ ssid="${SSID}"
    ...    \ \ psk="${pass}"
    ...    \ \ key_mgmt=WPA-PSK
    ...    }
    Create File    ${DIR}/wpa-${ns}.conf    ${conf}\n
    Start Process    ip    netns    exec    ${P}${ns}    wpa_supplicant    -i    wlan0    -c
    ...    ${DIR}/wpa-${ns}.conf    alias=wpa-${ns}    stdout=${DIR}/wpa-${ns}.log    stderr=STDOUT

Client State
    [Arguments]    ${ns}
    ${r}=    Run In    ${ns}    wpa_cli    -p    ${DIR}/wpa-${ns}    -i    wlan0    status
    ${m}=    Get Regexp Matches    ${r.stdout}    wpa_state=(\\w+)    1
    IF    not $m    RETURN    UNKNOWN
    RETURN    ${m[0]}

Client Is Associated
    [Arguments]    ${ns}
    ${s}=    Client State    ${ns}
    Should Be Equal    ${s}    COMPLETED

Disconnect Client
    [Arguments]    ${ns}
    Run Keyword And Ignore Error    Terminate Process    wpa-${ns}

Stop Virtual Radios
    IF    '${P}' == ''    RETURN
    Terminate All Processes    kill=True
    FOR    ${ns}    IN    ap    c1    c2
        Run Process    ip    netns    del    ${P}${ns}
    END
    Sleep    1s
    Run Process    modprobe    -r    mac80211_hwsim
