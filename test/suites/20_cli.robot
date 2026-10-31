*** Settings ***
Documentation     rpctl CLI behaviour: config validation, golden rendering, preflight
...               gating and the full apply / confirm / rollback lifecycle on a fake root.
Resource          ../resources/rpctl.resource
Test Tags         cli

*** Variables ***
${BASIC}          ${FIXTURES}/config/basic.toml

*** Test Cases ***
Version And Module List
    ${v}=    Run Ok    ${RPCTL}    --version
    Should Match Regexp    ${v}    ^rpctl \\d+\\.\\d+\\.\\d+
    ${m}=    Run Ok    ${RPCTL}    modules
    Should Contain    ${m}    base

Example And Fixture Configs Are Valid
    Run Ok    ${RPCTL}    --config    ${REPO}/configs/rp.example.toml    check
    Run Ok    ${RPCTL}    --config    ${BASIC}    check

Invalid Configs Are Rejected With Exit Code 3
    [Template]    Config Is Rejected
    catch-all-lan.toml       whole address space
    ssh-open-to-all.toml     every address
    iface-injection.toml     not a valid interface name
    host-bits.toml           host bits set
    unknown-key.toml         surprise
    timeout-range.toml       between 30 and 3600
    not-toml.toml            invalid TOML

Missing Config Is An Error
    ${r}=    Run Expecting    3    ${RPCTL}    --config    /nonexistent/rp.toml    check
    Should Contain    ${r.stdout}    cannot read

Unknown Module Is An Error
    ${r}=    Run Expecting    1    ${RPCTL}    --config    ${BASIC}    render    nope
    Should Contain    ${r.stdout}    unknown module

Rendered Base Files Match Golden Copies
    ${out}=    New Temp Dir
    Run Ok    ${RPCTL}    --config    ${BASIC}    render    base    --out    ${out}
    @{golden}=    List Files Recursively    ${FIXTURES}/golden/basic
    Length Should Be    ${golden}    5
    FOR    ${rel}    IN    @{golden}
        ${want}=    Get File    ${FIXTURES}/golden/basic/${rel}
        ${got}=    Get File    ${out}/${rel}
        Should Be Equal    ${got}    ${want}    msg=${rel} differs from golden copy
    END

Firewall Never Opens SSH To Everyone
    ${out}=    Run Ok    ${RPCTL}    --config    ${BASIC}    render    base
    Should Contain    ${out}    hook input priority filter; policy drop;
    Should Contain    ${out}    tcp dport 22 ip saddr @ssh_allow4 accept
    Should Not Match Regexp    ${out}    tcp dport 22 accept

Preflight Passes On A Healthy Root
    ${root}=    Create Fake Root
    ${out}=    Rpctl    ${root}    0    preflight    base
    Should Not Contain    ${out}    [FAIL]

Preflight Fails Without Carrier On The Management Interface
    ${root}=    Create Fake Root    carrier=0
    ${out}=    Rpctl    ${root}    2    preflight    base
    Should Contain    ${out}    no carrier

Preflight Blocks A Change That Would Lock Out The Current SSH Session
    ${root}=    Create Fake Root
    ${out}=    Rpctl    ${root}    2    preflight    base    env:SSH_CONNECTION=198.51.100.9 50000 192.0.2.10 22
    Should Contain    ${out}    lock you out
    ${ok}=    Rpctl    ${root}    0    preflight    base    env:SSH_CONNECTION=192.0.2.44 50000 192.0.2.10 22
    Should Contain    ${ok}    inside ssh allow-list

Preflight Refuses Key-Only SSH Without Authorized Keys
    ${root}=    Create Fake Root
    Rpctl    ${root}    2    preflight    base    config=${FIXTURES}/config/keys-only.toml
    Create File    ${root}/home/admin/.ssh/authorized_keys    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample admin@example\n
    Rpctl    ${root}    0    preflight    base    config=${FIXTURES}/config/keys-only.toml

Apply Refuses To Run When Preflight Fails
    ${root}=    Create Fake Root    carrier=0
    ${out}=    Rpctl    ${root}    2    apply    base
    Should Contain    ${out}    nothing was changed
    Managed Files Should Not Exist    ${root}

Dry Run Shows A Diff And Changes Nothing
    ${root}=    Create Fake Root
    ${out}=    Rpctl    ${root}    0    apply    base    --dry-run
    Should Contain    ${out}    dry run: 5 file(s) would change
    Should Contain    ${out}    +table inet rp {
    Should Contain    ${out}    would run: systemd-run --unit=rp-confirm-base
    Managed Files Should Not Exist    ${root}
    ${cmds}=    Recorded Commands    ${root}
    FOR    ${c}    IN    @{cmds}
        Should Not Match Regexp    ${c}    ^(nft -f|systemctl (restart|enable|reload)|sysctl --system)
    END

Apply Validates Before Loading And Arms The Dead-Man Timer
    ${root}=    Create Fake Root
    ${out}=    Rpctl    ${root}    0    apply    base
    Should Contain    ${out}    run `rpctl confirm` within 120s
    File Should Exist    ${root}/etc/rp/nftables.nft
    ${check}=    Index Of Command    ${root}    nft -c -f
    ${load}=    Index Of Command    ${root}    systemctl restart rp-firewall.service
    ${timer}=    Index Of Command    ${root}    systemd-run --unit=rp-confirm-base --on-active=120
    Should Be True    ${check} < ${load} < ${timer}

Second Apply Is A No-Op
    ${root}=    Create Fake Root
    Rpctl    ${root}    0    apply    base
    Remove File    ${root}/cmds.log
    ${out}=    Rpctl    ${root}    0    apply    base
    Should Contain    ${out}    already up to date
    @{cmds}=    Recorded Commands    ${root}
    FOR    ${c}    IN    @{cmds}
        Should Not Match Regexp    ${c}    ^(nft|systemctl|sysctl|systemd-run)
    END

Confirm Cancels The Automatic Rollback
    ${root}=    Create Fake Root
    Rpctl    ${root}    0    apply    base
    ${s}=    Rpctl    ${root}    0    status
    Should Contain    ${s}    applied=true confirmed=false
    ${c}=    Rpctl    ${root}    0    confirm
    Should Contain    ${c}    confirmed: base
    Index Of Command    ${root}    systemctl stop rp-confirm-base.timer
    ${s2}=    Rpctl    ${root}    0    status
    Should Contain    ${s2}    applied=true confirmed=true

Rollback Restores Pre-Existing Files And Removes New Ones
    ${root}=    Create Fake Root
    Create File    ${root}/etc/sysctl.d/90-rp-base.conf    original contents\n
    Rpctl    ${root}    0    apply    base
    ${out}=    Rpctl    ${root}    0    rollback    base
    Should Contain    ${out}    rolled back 5 file(s)
    ${restored}=    Get File    ${root}/etc/sysctl.d/90-rp-base.conf
    Should Be Equal    ${restored}    original contents\n
    File Should Not Exist    ${root}/etc/rp/nftables.nft
    ${disable}=    Index Of Command    ${root}    systemctl disable rp-firewall.service
    Should Be True    ${disable} >= 0

Failed Validation Leaves The System Untouched
    ${root}=    Create Fake Root
    ${out}=    Rpctl    ${root}    1    apply    base    fail=nft -c
    Should Contain    ${out}    validation failed
    Managed Files Should Not Exist    ${root}

Failed Post-Apply Step Rolls Back Automatically
    ${root}=    Create Fake Root
    ${out}=    Rpctl    ${root}    1    apply    base    fail=sshd -t
    Should Contain    ${out}    changes were rolled back
    Managed Files Should Not Exist    ${root}
    ${cmds}=    Recorded Commands    ${root}
    Should Not Contain Match    ${cmds}    systemd-run*

Rollback Without A Backup Is An Error
    ${root}=    Create Fake Root
    ${out}=    Rpctl    ${root}    1    rollback    base
    Should Contain    ${out}    no backup found

Status Reports JSON
    ${root}=    Create Fake Root
    ${out}=    Rpctl    ${root}    0    status    --json
    ${rows}=    Evaluate    json.loads($out)    modules=json
    Should Be Equal    ${rows[0]['module']}    base
    Should Be Equal As Integers    ${rows[0]['pending_changes']}    5

*** Keywords ***
Config Is Rejected
    [Arguments]    ${file}    ${message}
    ${r}=    Run Expecting    3    ${RPCTL}    --config    ${FIXTURES}/config/bad/${file}    check
    Should Contain    ${r.stdout}    ${message}
