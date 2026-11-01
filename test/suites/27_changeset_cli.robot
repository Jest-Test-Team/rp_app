*** Settings ***
Documentation     `rpctl changeset`: revision-checked patches, preflight (including the
...               management-client lockout check), apply with a device-local rollback timer,
...               confirm / expire / rollback, and the shared lock with classic `rpctl apply`.
Resource          ../resources/rpctl.resource
Test Tags         cli    changeset

*** Test Cases ***
Full Life Cycle Create Preflight Apply Confirm
    ${root}    ${cfg}=    Fresh Device
    ${rev}=    Revision    ${root}    ${cfg}
    ${cs}=    CS    ${root}    ${cfg}    0    create    base    --expected-revision    ${rev}
    ...    --patch    {"base.allow_mdns": false}
    Should Be Equal    ${cs['status']}    created
    Should Contain    ${cs['config_diff']}    +allow_mdns = false
    Should Not Contain    ${cs}    new_config
    ${cs}=    CS    ${root}    ${cfg}    0    preflight    ${cs['id']}    --peer    192.0.2.10
    Should Be Equal    ${cs['status']}    preflighted
    ${cs}=    CS    ${root}    ${cfg}    0    apply    ${cs['id']}    --confirm-secs    90
    Should Be Equal    ${cs['status']}    awaiting_confirm
    ${cmds}=    Get File    ${root}/cmds.log
    Should Match Regexp    ${cmds}    systemd-run --unit=rp-changeset-${cs['id']} --on-active=90 .* changeset expire ${cs['id']}
    ${text}=    Get File    ${cfg}
    Should Contain    ${text}    allow_mdns = false
    ${cs}=    CS    ${root}    ${cfg}    0    confirm    ${cs['id']}
    Should Be Equal    ${cs['status']}    confirmed

Timer Expiry Restores The Config And Files
    ${root}    ${cfg}=    Fresh Device
    ${before}=    Get File    ${cfg}
    ${id}=    Applied Change    ${root}    ${cfg}    {"base.allow_mdns": false}
    ${cs}=    CS    ${root}    ${cfg}    0    expire    ${id}
    Should Be Equal    ${cs['status']}    rolled_back
    ${after}=    Get File    ${cfg}
    Should Be Equal    ${before}    ${after}
    File Should Not Exist    ${root}/etc/rp/nftables.nft

Stale Revision Is A Conflict With Exit Code 4
    ${root}    ${cfg}=    Fresh Device
    ${rev}=    Revision    ${root}    ${cfg}
    Append To File    ${cfg}    \n# hand edit\n
    ${r}=    Rpctl    ${root}    4    --json    changeset    create    base    --expected-revision    ${rev}
    ...    --patch    {"base.allow_mdns": false}    config=${cfg}
    Should Contain    ${r}    revision

Non Whitelisted Or Invalid Patches Exit 3
    ${root}    ${cfg}=    Fresh Device
    ${rev}=    Revision    ${root}    ${cfg}
    FOR    ${patch}    IN    {"device.wan_if": "wlan0"}    {"agent.token_file": "/tmp/t"}
    ...    {"ssh.allow_from": ["0.0.0.0/0"]}    {"base.confirm_timeout_secs": 5}
    ...    {"base.allow_mdns": "yes; reboot"}
        Rpctl    ${root}    3    changeset    create    base    --expected-revision    ${rev}
        ...    --patch    ${patch}    config=${cfg}
    END

Preflight Refuses A Change That Would Cut Off The App
    ${root}    ${cfg}=    Fresh Device
    ${rev}=    Revision    ${root}    ${cfg}
    ${cs}=    CS    ${root}    ${cfg}    0    create    base    --expected-revision    ${rev}
    ...    --patch    {"base.allow_mdns": false}
    ${cs}=    CS    ${root}    ${cfg}    2    preflight    ${cs['id']}    --peer    198.51.100.9
    Should Be Equal    ${cs['status']}    created
    ${names}=    Evaluate    [c['name'] for c in $cs['checks'] if c['status'] == 'fail']
    Should Contain    ${names}    api_lockout
    Rpctl    ${root}    1    changeset    apply    ${cs['id']}    config=${cfg}

Failed On Device Check Rolls Back And Exits 2
    ${root}    ${cfg}=    Fresh Device
    ${before}=    Get File    ${cfg}
    ${rev}=    Revision    ${root}    ${cfg}
    ${cs}=    CS    ${root}    ${cfg}    0    create    base    --expected-revision    ${rev}
    ...    --patch    {"base.allow_mdns": false}
    CS    ${root}    ${cfg}    0    preflight    ${cs['id']}
    ${out}=    Rpctl    ${root}    2    --json    changeset    apply    ${cs['id']}
    ...    config=${cfg}    fail=nft list table
    ${after}=    Get File    ${cfg}
    Should Be Equal    ${before}    ${after}
    Should Contain    ${out}    post-apply checks failed

Path Traversal In Ids Is Rejected
    ${root}    ${cfg}=    Fresh Device
    ${r}=    Rpctl    ${root}    1    changeset    show    ../../../etc/passwd    config=${cfg}
    Should Contain    ${r}    unknown change set

Secrets Are Stored Root Only And Never Printed
    ${root}    ${cfg}=    Fresh Device
    ${r}=    Run Expecting    0    ${RPCTL}    --config    ${cfg}    --root    ${root}
    ...    secret    set    ap_passphrase    stdin=correct horse battery
    Should Not Contain    ${r.stdout}    horse
    Should Contain    ${r.stdout}    fingerprint
    ${mode}=    Evaluate    oct(os.stat($root + '/etc/rp/ap.psk').st_mode & 0o777)    modules=os
    Should Be Equal    ${mode}    0o600
    ${bad}=    Run Expecting    1    ${RPCTL}    --config    ${cfg}    --root    ${root}
    ...    secret    set    tailscale_auth_key    stdin=not-a-key
    Should Not Contain    ${bad.stdout}    not-a-key
    ${st}=    Run Ok    ${RPCTL}    --config    ${cfg}    --root    ${root}    secret    status
    Should Match Regexp    ${st}    ap_passphrase\\s+set
    Should Match Regexp    ${st}    tailscale_auth_key\\s+not set

*** Keywords ***
Fresh Device
    ${root}=    Create Fake Root
    Create File    ${root}/sys/class/net/eth0/device/vendor    x
    ${cfg}=    Set Variable    ${root}/rp.toml
    Copy File    ${FIXTURES}/config/basic.toml    ${cfg}
    RETURN    ${root}    ${cfg}

Revision
    [Arguments]    ${root}    ${cfg}
    ${out}=    Rpctl    ${root}    0    changeset    revision    config=${cfg}
    RETURN    ${out.strip()}

CS
    [Documentation]    rpctl --json changeset ...; returns the parsed change set.
    [Arguments]    ${root}    ${cfg}    ${rc}    @{args}
    ${out}=    Rpctl    ${root}    ${rc}    --json    changeset    @{args}    config=${cfg}
    ${start}=    Evaluate    $out.index('{')
    ${cs}=    Evaluate    json.loads($out[${start}:])    modules=json
    RETURN    ${cs}

Applied Change
    [Arguments]    ${root}    ${cfg}    ${patch}
    ${rev}=    Revision    ${root}    ${cfg}
    ${cs}=    CS    ${root}    ${cfg}    0    create    base    --expected-revision    ${rev}    --patch    ${patch}
    CS    ${root}    ${cfg}    0    preflight    ${cs['id']}
    ${cs}=    CS    ${root}    ${cfg}    0    apply    ${cs['id']}
    Should Be Equal    ${cs['status']}    awaiting_confirm
    RETURN    ${cs['id']}
