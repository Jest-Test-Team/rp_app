*** Settings ***
Documentation     Signed updates: a real minisign key and a release packed from this build,
...               installed on a fake root with `rpctl update` — signature and checksum
...               verification, self-test against the live config, all binaries switched
...               together (old ones adopted), switch-back, rollback and status.
Resource          ../resources/rpctl.resource
Suite Setup       Make Signed Release
Test Tags         installer    update

*** Variables ***
${TRIPLE}         armv7-unknown-linux-gnueabihf
@{BINS}           rpctl    rp-dns    rp-agent    rp-mcp    rp-privd    rp-api

*** Test Cases ***
Signed Release Installs And Switches Every Binary
    ${root}=    Old Device    ${KEYDIR}/minisign.pub
    ${out}=    Update    ${root}    0    install    --target    ${TRIPLE}    --settle-secs    0    --tag    v0.2.0    --base-url    file://${REL}
    ${r}=    Evaluate    json.loads($out)    modules=json
    Should Be Equal    ${r['previous']}    v0.1.0
    FOR    ${b}    IN    @{BINS}
        ${link}=    Evaluate    os.readlink($root + '/usr/local/bin/${b}')    modules=os
        Should Be Equal    ${link}    /opt/rp/releases/v0.2.0/bin/${b}
        File Should Exist    ${root}/opt/rp/releases/v0.1.0/bin/${b}    msg=old ${b} kept for rollback
    END
    ${cmds}=    Get File    ${root}/cmds.log
    Should Contain    ${cmds}    releases/v0.2.0/bin/rpctl --config
    ${st}=    Update    ${root}    0    status
    ${s}=    Evaluate    json.loads($st)    modules=json
    Should Be Equal    ${s['live']}    v0.2.0
    Should Be Equal    ${s['current']}    v0.2.0

Rollback Returns To The Adopted Release
    ${root}=    Old Device    ${KEYDIR}/minisign.pub
    Update    ${root}    0    install    --target    ${TRIPLE}    --settle-secs    0    --tag    v0.2.0    --base-url    file://${REL}
    Update    ${root}    0    rollback    --settle-secs    0
    ${link}=    Evaluate    os.readlink($root + '/usr/local/bin/rpctl')    modules=os
    Should Be Equal    ${link}    /opt/rp/releases/v0.1.0/bin/rpctl

Unsigned Releases Are Refused
    ${unsigned}=    New Temp Dir
    Copy File    ${REL}/SHA256SUMS    ${unsigned}/
    Copy File    ${REL}/rp-${TRIPLE}.tar.gz    ${unsigned}/
    ${root}=    Old Device    ${KEYDIR}/minisign.pub
    ${r}=    Update    ${root}    1    install    --target    ${TRIPLE}    --settle-secs    0    --tag    v0.2.0    --base-url    file://${unsigned}
    Should Contain    ${r}    SHA256SUMS.minisig
    Nothing Was Switched    ${root}

A Signature From Another Key Is Refused
    ${other}=    New Temp Dir
    Run Ok    ${PROBE}    release    keygen    --out-dir    ${other}
    ${root}=    Old Device    ${other}/minisign.pub
    ${r}=    Update    ${root}    1    install    --target    ${TRIPLE}    --settle-secs    0    --tag    v0.2.0    --base-url    file://${REL}
    Should Contain    ${r}    signature check failed
    Nothing Was Switched    ${root}

A Tampered Archive Is Refused
    ${bad}=    New Temp Dir
    Copy File    ${REL}/SHA256SUMS    ${bad}/
    Copy File    ${REL}/SHA256SUMS.minisig    ${bad}/
    Copy File    ${REL}/rp-${TRIPLE}.tar.gz    ${bad}/
    Append To Binary File    ${bad}/rp-${TRIPLE}.tar.gz    garbage
    ${root}=    Old Device    ${KEYDIR}/minisign.pub
    ${r}=    Update    ${root}    1    install    --target    ${TRIPLE}    --settle-secs    0    --tag    v0.2.0    --base-url    file://${bad}
    Should Contain    ${r}    checksum mismatch
    Nothing Was Switched    ${root}

A Release That Rejects The Live Config Never Goes Live
    ${root}=    Old Device    ${KEYDIR}/minisign.pub
    ${r}=    Update    ${root}    1    install    --target    ${TRIPLE}    --settle-secs    0    --tag    v0.2.0    --base-url    file://${REL}
    ...    fail=${root}/opt/rp/releases/v0.2.0/bin/rpctl --config
    Should Contain    ${r}    self-test
    Nothing Was Switched    ${root}

Dry Run Verifies Without Switching
    ${root}=    Old Device    ${KEYDIR}/minisign.pub
    ${out}=    Update    ${root}    0    install    --target    ${TRIPLE}    --settle-secs    0    --tag    v0.2.0    --base-url    file://${REL}    --dry-run
    Should Contain    ${out}    signature and checksum verified
    Nothing Was Switched    ${root}

No Signing Key Means No Updates
    ${root}=    Old Device    ${NONE}
    ${r}=    Update    ${root}    1    install    --target    ${TRIPLE}    --settle-secs    0    --tag    v0.2.0    --base-url    file://${REL}
    Should Contain    ${r}    no update signing key

The Key Is Encrypted And The Signature Verifies With The Public Key
    # minisign secret key layout: signature algorithm "Ed", then KDF "Sc" (scrypt) when encrypted.
    ${kdf}=    Evaluate    base64.b64decode(open($KEYDIR + '/minisign.key').read().splitlines()[1])[2:4]    modules=base64
    Should Be Equal    ${kdf}    ${{ b'Sc' }}
    ${r}=    Run Expecting    1    ${PROBE}    release    sign    --secret-key-file    ${KEYDIR}/minisign.key
    ...    --file    ${REL}/SHA256SUMS
    ${mode}=    Evaluate    oct(os.stat($KEYDIR + '/minisign.key').st_mode & 0o777)    modules=os
    Should Be Equal    ${mode}    0o600
    ${v}=    Run Ok    ${PROBE}    release    verify    --public-key-file    ${KEYDIR}/minisign.pub    --file    ${REL}/SHA256SUMS
    Should Contain    ${v}    signature OK

*** Keywords ***
Make Signed Release
    ${keys}=    New Temp Dir
    ${rel}=    New Temp Dir
    Set Environment Variable    RP_TEST_KEY_PASSWORD    robot-test-only
    Run Ok    ${PROBE}    release    keygen    --out-dir    ${keys}    --password-env    RP_TEST_KEY_PASSWORD
    Run Ok    ${PROBE}    release    pack    --bin-dir    ${REPO}/target/debug    --target    ${TRIPLE}    --out    ${rel}
    Run Ok    ${PROBE}    release    sign    --secret-key-file    ${keys}/minisign.key
    ...    --password-env    RP_TEST_KEY_PASSWORD    --file    ${rel}/SHA256SUMS
    Set Suite Variable    ${KEYDIR}    ${keys}
    Set Suite Variable    ${REL}    ${rel}

Old Device
    [Documentation]    A v0.1-style install: plain binaries in /usr/local/bin, a config, the key.
    [Arguments]    ${pubkey}
    ${root}=    Create Fake Root
    FOR    ${b}    IN    @{BINS}
        Create File    ${root}/usr/local/bin/${b}    old ${b}
    END
    Copy File    ${FIXTURES}/config/basic.toml    ${root}/etc/rp/rp.toml
    IF    $pubkey is not None    Copy File    ${pubkey}    ${root}/etc/rp/minisign.pub
    RETURN    ${root}

Update
    [Arguments]    ${root}    ${rc}    @{args}    ${fail}=${EMPTY}
    ${r}=    Run Expecting    ${rc}    ${RPCTL}    --json    --config    ${root}/etc/rp/rp.toml    --root    ${root}
    ...    --record-commands    ${root}/cmds.log
    ...    --fake-output    ${root}/usr/local/bin/rpctl --version\=rpctl 0.1.0
    ...    --fail-commands    ${fail}
    ...    update    @{args}
    RETURN    ${r.stdout}

Nothing Was Switched
    [Arguments]    ${root}
    ${is}=    Evaluate    os.path.islink($root + '/usr/local/bin/rpctl')    modules=os
    Should Not Be True    ${is}
    ${t}=    Get File    ${root}/usr/local/bin/rpctl
    Should Be Equal    ${t}    old rpctl

Append To Binary File
    [Arguments]    ${path}    ${text}
    Evaluate    open($path, 'ab').write($text.encode())
