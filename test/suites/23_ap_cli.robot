*** Settings ***
Documentation     rpctl ap module: golden rendering, secrets never rendered, passphrase
...               handling, lockout-proof preflight, apply ordering and rollback that
...               hands the interface back to NetworkManager.
Resource          ../resources/rpctl.resource
Test Tags         cli    ap

*** Variables ***
${APCFG}          ${FIXTURES}/config/ap.toml
${PASS}           correct horse battery

*** Test Cases ***
Rendered AP Files Match Golden Copies
    ${out}=    New Temp Dir
    Run Ok    ${RPCTL}    --config    ${APCFG}    render    ap    --out    ${out}
    @{files}=    List Files Recursively    ${FIXTURES}/golden/ap
    Length Should Be    ${files}    7
    FOR    ${rel}    IN    @{files}
        ${want}=    Get File    ${FIXTURES}/golden/ap/${rel}
        ${got}=    Get File    ${out}/${rel}
        Should Be Equal    ${got}    ${want}    msg=${rel} differs from golden copy
    END

Hostapd Is WPA2 With Client Isolation And Holds No Secret
    ${out}=    Run Ok    ${RPCTL}    --config    ${APCFG}    render    ap
    FOR    ${line}    IN    wpa=2    rsn_pairwise=CCMP    ap_isolate=1    country_code=TW
    ...    wpa_psk_file=/etc/rp/ap.psk    port=0
        Should Contain    ${out}    ${line}
    END
    Should Not Contain    ${out}    wpa_passphrase

AP Clients Are Kept Off The LAN And Each Other
    ${out}=    Run Ok    ${RPCTL}    --config    ${APCFG}    render    ap
    ${hairpin}=    Evaluate    $out.index('iifname "wlan0" oifname "wlan0" drop')
    ${block}=    Evaluate    $out.index('iifname "wlan0" ip daddr @ap_block4 drop')
    ${accept}=    Evaluate    $out.index('iifname "wlan0" oifname "eth0" accept')
    Should Be True    ${hairpin} < ${accept} and ${block} < ${accept}
    Should Contain    ${out}    iifname "wlan0" meta nfproto ipv6 drop
    Should Contain    ${out}    tcp dport 853

Set Passphrase Writes A Root-Only File And Never Prints It
    ${root}=    Create Fake Root
    ${r}=    Run Process    ${RPCTL}    --config    ${APCFG}    --root    ${root}    ap    set-passphrase
    ...    --stdin    stdin=${PASS}\n    stderr=STDOUT
    Should Be Equal As Integers    ${r.rc}    0    msg=${r.stdout}
    Should Not Contain    ${r.stdout}    ${PASS}
    ${content}=    Get File    ${root}/etc/rp/ap.psk
    Should Be Equal    ${content}    00:00:00:00:00:00 ${PASS}\n
    ${mode}=    Evaluate    oct(os.stat($root + '/etc/rp/ap.psk').st_mode & 0o777)    modules=os
    Should Be Equal    ${mode}    0o600

Weak Passphrases Are Rejected
    [Template]    Passphrase Is Rejected
    short
    ${{ 'x' * 64 }}

Preflight Requires A Passphrase
    ${root}=    Create Fake Root
    ${out}=    Rpctl    ${root}    2    preflight    ap    config=${APCFG}
    Should Contain    ${out}    rpctl ap set-passphrase

Preflight Refuses An AP On The Management Interface
    ${tmp}=    New Temp Dir
    ${cfg}=    Get File    ${APCFG}
    ${cfg}=    Replace String    ${cfg}    wan_if = "eth0"    wan_if = "eth0"\nmgmt_if = "wlan0"
    Create File    ${tmp}/rp.toml    ${cfg}
    ${r}=    Run Expecting    3    ${RPCTL}    --config    ${tmp}/rp.toml    check
    Should Contain    ${r.stdout}    the AP would cut you off

AP Requires Base And Applies In A Safe Order
    ${root}=    Create Fake Root
    Run Process    ${RPCTL}    --config    ${APCFG}    --root    ${root}    ap    set-passphrase    --stdin
    ...    stdin=${PASS}\n
    ${needs}=    Rpctl    ${root}    1    apply    ap    config=${APCFG}
    Should Contain    ${needs}    needs 'base' applied first
    Rpctl    ${root}    0    apply    base    config=${APCFG}
    Remove File    ${root}/cmds.log
    ${out}=    Rpctl    ${root}    0    apply    ap    config=${APCFG}
    Should Contain    ${out}    sudo rpctl rollback ap
    ${nft}=    Index Of Command    ${root}    nft -c -f
    ${dhcp}=    Index Of Command    ${root}    dnsmasq --test
    ${nm}=    Index Of Command    ${root}    nmcli general reload conf
    ${fw}=    Index Of Command    ${root}    systemctl reload-or-restart rp-firewall.service
    ${ap}=    Index Of Command    ${root}    systemctl restart rp-ap-hostapd.service
    Should Be True    ${nft} < ${nm} and ${dhcp} < ${nm} < ${fw} < ${ap}
    File Should Exist    ${root}/etc/NetworkManager/conf.d/90-rp-ap.conf

Rollback Hands The Interface Back To NetworkManager
    ${root}=    Create Fake Root
    Run Process    ${RPCTL}    --config    ${APCFG}    --root    ${root}    ap    set-passphrase    --stdin
    ...    stdin=${PASS}\n
    Rpctl    ${root}    0    apply    base    config=${APCFG}
    Rpctl    ${root}    0    apply    ap    config=${APCFG}
    Remove File    ${root}/cmds.log
    Rpctl    ${root}    0    rollback    ap    config=${APCFG}
    File Should Not Exist    ${root}/etc/NetworkManager/conf.d/90-rp-ap.conf
    File Should Not Exist    ${root}/etc/rp/nft.d/60-ap.nft
    ${stop}=    Index Of Command    ${root}    systemctl disable --now rp-ap-dnsmasq.service rp-ap-hostapd.service
    ${reload}=    Index Of Command    ${root}    nmcli general reload conf
    Should Be True    ${stop} < ${reload}
    File Should Exist    ${root}/etc/rp/ap.psk

Failed AP Start Rolls Back And Restores NetworkManager
    ${root}=    Create Fake Root
    Run Process    ${RPCTL}    --config    ${APCFG}    --root    ${root}    ap    set-passphrase    --stdin
    ...    stdin=${PASS}\n
    Rpctl    ${root}    0    apply    base    config=${APCFG}
    ${out}=    Rpctl    ${root}    1    apply    ap    config=${APCFG}    fail=systemctl is-active
    Should Contain    ${out}    changes were rolled back
    File Should Not Exist    ${root}/etc/NetworkManager/conf.d/90-rp-ap.conf

*** Keywords ***
Passphrase Is Rejected
    [Arguments]    ${pass}
    ${root}=    Create Fake Root
    ${r}=    Run Process    ${RPCTL}    --config    ${APCFG}    --root    ${root}    ap    set-passphrase
    ...    --stdin    stdin=${pass}\n    stderr=STDOUT
    Should Not Be Equal As Integers    ${r.rc}    0
    Should Contain    ${r.stdout}    8-63 printable
    File Should Not Exist    ${root}/etc/rp/ap.psk
