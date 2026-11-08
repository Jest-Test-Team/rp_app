*** Settings ***
Documentation     rpctl dns block / unblock / list / import: validated, de-duplicated,
...               comment-preserving edits of the blocklist file, followed by a reload.
Resource          ../resources/rpctl.resource
Test Tags         cli    dns

*** Variables ***
${CFG}            ${FIXTURES}/config/dns-list.toml

*** Test Cases ***
Block Creates The File, Normalises And De-duplicates
    ${root}=    Create Fake Root
    ${out}=    Dns    ${root}    block    Ads.Example.COM.    *.tracker.example    ads.example.com
    Should Contain    ${out}    blocked 2 new domain(s) (2 total)
    Should Contain    ${out}    rp-dns reloaded
    ${list}=    List Only    ${root}
    Should Be Equal    ${list.strip()}    ads.example.com\ntracker.example
    ${mode}=    Evaluate    oct(os.stat($root + '/etc/rp/dns/blocklist.txt').st_mode & 0o777)    modules=os
    Should Be Equal    ${mode}    0o644
    @{cmds}=    Recorded Commands    ${root}
    Should Contain    ${cmds}    systemctl reload rp-dns.service

Invalid Domains Are Rejected And Nothing Is Written
    ${root}=    Create Fake Root
    ${r}=    Run Expecting    1    ${RPCTL}    --config    ${CFG}    --root    ${root}
    ...    --record-commands    ${root}/cmds.log    dns    block    good.example    bad domain;rm
    Should Contain    ${r.stdout}    is not a valid domain
    File Should Not Exist    ${root}/etc/rp/dns/blocklist.txt

Unblock Removes Plain And Hosts-Format Lines And Keeps Comments
    ${root}=    Create Fake Root
    Create File    ${root}/etc/rp/dns/blocklist.txt    \# my notes\n0.0.0.0 ads.example\nkeep.example\ntracker.example\n
    ${out}=    Dns    ${root}    unblock    ads.example    tracker.example
    Should Contain    ${out}    unblocked 2 line(s)
    ${t}=    Get File    ${root}/etc/rp/dns/blocklist.txt
    Should Be Equal    ${t}    \# my notes\nkeep.example\n

No Change Means No Reload
    ${root}=    Create Fake Root
    Dns    ${root}    block    a.example
    Remove File    ${root}/cmds.log
    ${out}=    Dns    ${root}    block    a.example
    Should Contain    ${out}    blocked 0 new domain(s)
    @{cmds}=    Recorded Commands    ${root}
    Should Not Contain    ${cmds}    systemctl reload rp-dns.service

Import Merges A Hosts File And Skips Junk
    ${root}=    Create Fake Root
    ${tmp}=    New Temp Dir
    Create File    ${tmp}/hosts.txt    127.0.0.1 localhost\n0.0.0.0 one.example\n0.0.0.0 two.example \# c\nnot valid!\n:: three.example\n
    Dns    ${root}    block    one.example
    ${out}=    Dns    ${root}    import    ${tmp}/hosts.txt
    Should Contain    ${out}    imported 2 new domain(s), skipped 2 invalid line(s)
    ${list}=    List Only    ${root}
    Should Be Equal    ${list.strip()}    one.example\nthree.example\ntwo.example

Import From A URL Requires https And Uses curl Safely
    ${root}=    Create Fake Root
    ${r}=    Run Expecting    1    ${RPCTL}    --config    ${CFG}    --root    ${root}    dns    import
    ...    --url    http://insecure.example/list.txt
    Should Contain    ${r.stdout}    only https://
    Run Expecting    0    ${RPCTL}    --config    ${CFG}    --root    ${root}
    ...    --record-commands    ${root}/cmds.log    dns    import    --url    https://lists.example/hosts
    ${cmds}=    Get File    ${root}/cmds.log
    Should Contain    ${cmds}    curl -fsSL --proto =https --max-filesize 50000000 -o
    Should Contain    ${cmds}    https://lists.example/hosts

Feeds Are Fetched Over https With Limits And Failures Keep DNS Running
    [Documentation]    rpctl dns update-feeds (run daily by rp-dns-feeds.timer): only catalogue
    ...                URLs, curl limited to https / size / time; a failed download is reported
    ...                per feed (exit 1 for the timer) and never breaks the DNS firewall.
    ${root}=    Create Fake Root
    ${r}=    Run Expecting    1    ${RPCTL}    --config    ${FIXTURES}/config/dns-feeds.toml    --root    ${root}
    ...    --record-commands    ${root}/cmds.log    dns    update-feeds
    ${cmds}=    Get File    ${root}/cmds.log
    Should Contain    ${cmds}    curl -fsSL --proto =https --max-time 300 --max-filesize 30000000 -o
    Should Contain    ${cmds}    https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
    Should Contain    ${cmds}    https://phishing.army/download/phishing_army_blocklist.txt
    Should Contain    ${r.stdout}    NOT updated
    ${status}=    Get File    ${root}/var/lib/rp-dns-feeds/status.json
    Should Contain    ${status}    "id": "urlhaus"
    ${list}=    Run Expecting    0    ${RPCTL}    --config    ${FIXTURES}/config/dns-feeds.toml    --root    ${root}
    ...    dns    feeds
    Should Contain    ${list.stdout}    [x] stevenblack
    Should Contain    ${list.stdout}    [ ] hagezi_tif_mini

Unknown Feed Ids Are Refused By Validation
    ${root}=    Create Fake Root
    ${cfg}=    Set Variable    ${root}/bad-feeds.toml
    ${t}=    Get File    ${FIXTURES}/config/dns-feeds.toml
    Create File    ${cfg}    ${t.replace('"urlhaus"', '"https://evil.example/list"')}
    ${r}=    Run Expecting    3    ${RPCTL}    --config    ${cfg}    --root    ${root}    check
    Should Contain    ${r.stdout}${r.stderr}    is not a known feed

*** Keywords ***
List Only
    [Documentation]    stdout only (the count goes to stderr).
    [Arguments]    ${root}
    ${r}=    Run Process    ${RPCTL}    --config    ${CFG}    --root    ${root}    dns    list
    Should Be Equal As Integers    ${r.rc}    0
    RETURN    ${r.stdout}

Dns
    [Arguments]    ${root}    @{args}
    ${r}=    Run Expecting    0    ${RPCTL}    --config    ${CFG}    --root    ${root}
    ...    --record-commands    ${root}/cmds.log    dns    @{args}
    RETURN    ${r.stdout}
