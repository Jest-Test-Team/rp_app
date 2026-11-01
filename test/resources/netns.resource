*** Settings ***
Documentation     Linux network-namespace topology for integration tests (root only).
...
...               lan (192.0.2.50) ─┐
...               rp eth0 (192.0.2.10) ─ br0 home (192.0.2.1 | 203.0.113.1) ── inet (203.0.113.10)
...               cli (198.51.100.2/25) ── rp "wg0" (198.51.100.1/25)
...               iot (198.51.100.130/25) ── rp "wlan0" (198.51.100.129/25)
...
...               "wg0" is a veth standing in for the VPN interface, so the real
...               rendered nftables rules are exercised without needing a VPN.
...               Documentation address ranges only — nothing leaves the host.
Resource          common.resource

*** Variables ***
${NS}             ${EMPTY}

*** Keywords ***
Require Root On Linux
    ${linux}=    Is Linux
    Skip If    not ${linux}    network namespaces need Linux
    ${uid}=    Evaluate    os.geteuid()    modules=os
    Skip If    ${uid} != 0    needs root (RP_ALLOW_ROOT=1 sudo -E test/run.sh integration)
    Require Tool    nft
    Require Tool    ip

Sh
    [Documentation]    Run an argv in the root namespace; fail on error.
    [Arguments]    @{argv}
    ${r}=    Run Process    @{argv}    stderr=STDOUT
    Should Be Equal As Integers    ${r.rc}    0    msg=${argv}: ${r.stdout}
    RETURN    ${r.stdout}

In NS
    [Documentation]    Run an argv inside namespace ${name}; returns the result object.
    [Arguments]    ${name}    @{argv}    ${timeout}=15s
    ${r}=    Run Process    ip    netns    exec    ${NS}${name}    @{argv}
    ...    stderr=STDOUT    timeout=${timeout}
    RETURN    ${r}

Veth Into
    [Documentation]    Create a veth pair: ${a_ns}/${a_if} <-> ${b_ns}/${b_if}.
    [Arguments]    ${a_ns}    ${a_if}    ${b_ns}    ${b_if}
    ${tmp_a}=    Evaluate    'v' + __import__('secrets').token_hex(4)
    ${tmp_b}=    Evaluate    'v' + __import__('secrets').token_hex(4)
    Sh    ip    link    add    ${tmp_a}    type    veth    peer    name    ${tmp_b}
    Sh    ip    link    set    ${tmp_a}    netns    ${NS}${a_ns}
    Sh    ip    link    set    ${tmp_b}    netns    ${NS}${b_ns}
    Sh    ip    -n    ${NS}${a_ns}    link    set    ${tmp_a}    name    ${a_if}
    Sh    ip    -n    ${NS}${b_ns}    link    set    ${tmp_b}    name    ${b_if}
    Sh    ip    -n    ${NS}${a_ns}    link    set    ${a_if}    up
    Sh    ip    -n    ${NS}${b_ns}    link    set    ${b_if}    up

Create Topology
    Require Root On Linux
    ${prefix}=    Evaluate    'rpt' + __import__('secrets').token_hex(3) + '-'
    Set Suite Variable    ${NS}    ${prefix}
    FOR    ${n}    IN    home    rp    lan    inet    cli    iot
        Sh    ip    netns    add    ${NS}${n}
        Sh    ip    -n    ${NS}${n}    link    set    lo    up
    END
    Sh    ip    -n    ${NS}home    link    add    br0    type    bridge
    Sh    ip    -n    ${NS}home    link    set    br0    up
    Sh    ip    -n    ${NS}home    addr    add    192.0.2.1/24    dev    br0
    Veth Into    rp    eth0    home    p-rp
    Veth Into    lan    eth0    home    p-lan
    Sh    ip    -n    ${NS}home    link    set    p-rp    master    br0
    Sh    ip    -n    ${NS}home    link    set    p-lan    master    br0
    Veth Into    inet    eth0    home    up0
    Veth Into    cli    eth0    rp    wg0
    Veth Into    iot    eth0    rp    wlan0
    Sh    ip    -n    ${NS}home    addr    add    203.0.113.1/24    dev    up0
    Sh    ip    -n    ${NS}inet    addr    add    203.0.113.10/24    dev    eth0
    Sh    ip    -n    ${NS}inet    route    add    192.0.2.0/24    via    203.0.113.1
    # Return routes to the VPN subnet: without them isolation tests would pass
    # even with no firewall (replies could never come back). With them, only the
    # firewall stands between VPN clients and the LAN — the control test proves it.
    Sh    ip    -n    ${NS}inet    route    add    198.51.100.0/24    via    203.0.113.1
    Sh    ip    -n    ${NS}home    route    add    198.51.100.0/24    via    192.0.2.10
    Sh    ip    -n    ${NS}rp    addr    add    192.0.2.10/24    dev    eth0
    Sh    ip    -n    ${NS}rp    route    add    default    via    192.0.2.1
    Sh    ip    -n    ${NS}rp    addr    add    198.51.100.1/25    dev    wg0
    Sh    ip    -n    ${NS}rp    addr    add    198.51.100.129/25    dev    wlan0
    Sh    ip    -n    ${NS}lan    addr    add    192.0.2.50/24    dev    eth0
    Sh    ip    -n    ${NS}lan    route    add    default    via    192.0.2.1
    Sh    ip    -n    ${NS}lan    route    add    198.51.100.0/24    via    192.0.2.10
    Sh    ip    -n    ${NS}cli    addr    add    198.51.100.2/25    dev    eth0
    Sh    ip    -n    ${NS}cli    route    add    default    via    198.51.100.1
    Sh    ip    -n    ${NS}iot    addr    add    198.51.100.130/25    dev    eth0
    Sh    ip    -n    ${NS}iot    route    add    default    via    198.51.100.129
    # Only the home router forwards unconditionally. The rp namespace forwards
    # only if the rendered module sysctl.d files say so (see Load Firewall), so a
    # module that forgets to enable forwarding fails its internet-access tests.
    Sh    ip    netns    exec    ${NS}home    sysctl    -qw    net.ipv4.ip_forward\=1
    # Plain servers: an "internet" web server, a LAN web server and an sshd stand-in on the Pi.
    Start Process    ip    netns    exec    ${NS}inet    python3    -u    -m    http.server    8080
    ...    --bind    203.0.113.10    alias=inet-http    stderr=${OUTPUT_DIR}/${NS}inet-http.log
    Start Process    ip    netns    exec    ${NS}lan    python3    -m    http.server    8080
    ...    --bind    192.0.2.50    alias=lan-http
    Start Process    ip    netns    exec    ${NS}rp    python3    -m    http.server    22
    ...    --bind    0.0.0.0    alias=rp-ssh
    # Stand-ins: the Pi's DNS port (TCP 53) and a web UI on an IoT device.
    Start Process    ip    netns    exec    ${NS}rp    python3    -m    http.server    53
    ...    --bind    0.0.0.0    alias=rp-dns53
    Start Process    ip    netns    exec    ${NS}iot    python3    -m    http.server    8080
    ...    --bind    198.51.100.130    alias=iot-http
    # TCP echo on the "internet" host, for long-lived connection tests.
    ${echo}=    Catenate    SEPARATOR=\n
    ...    import socketserver
    ...    class H(socketserver.BaseRequestHandler):
    ...    \ \ \ \ def handle(self):
    ...    \ \ \ \ \ \ \ \ while True:
    ...    \ \ \ \ \ \ \ \ \ \ \ \ d = self.request.recv(64)
    ...    \ \ \ \ \ \ \ \ \ \ \ \ if not d: return
    ...    \ \ \ \ \ \ \ \ \ \ \ \ self.request.sendall(d)
    ...    socketserver.ThreadingTCPServer.allow_reuse_address = True
    ...    socketserver.ThreadingTCPServer(('203.0.113.10', 7777), H).serve_forever()
    Start Process    ip    netns    exec    ${NS}inet    python3    -c    ${echo}    alias=inet-echo
    # A DNS-over-TLS stand-in on the "internet" host (TCP 853).
    Start Process    ip    netns    exec    ${NS}inet    python3    -m    http.server    853
    ...    --bind    203.0.113.10    alias=inet-dot
    Sleep    1s

Destroy Topology
    IF    '${NS}' == ''    RETURN
    Terminate All Processes    kill=True
    FOR    ${n}    IN    home    rp    lan    inet    cli    iot
        Run Process    ip    netns    del    ${NS}${n}
    END

Load Firewall
    [Documentation]    Replace the rp namespace's ruleset with a rendered file and apply
    ...    the IPv4 forwarding setting from the same render's sysctl.d files.
    [Arguments]    ${file}
    ${dir}=    Evaluate    $file.split('/etc/rp/')[0]
    ${fwd}=    Evaluate
    ...    int(any('net.ipv4.ip_forward = 1' in open(p).read() for p in glob.glob($dir + '/etc/sysctl.d/*.conf')))
    ...    modules=glob
    ${s}=    In NS    rp    sysctl    -qw    net.ipv4.ip_forward\=${fwd}
    Should Be Equal As Integers    ${s.rc}    0    msg=sysctl failed: ${s.stdout}
    ${r}=    In NS    rp    nft    -f    ${file}
    Should Be Equal As Integers    ${r.rc}    0    msg=nft load failed: ${r.stdout}

Clear Firewall
    In NS    rp    nft    flush    ruleset

HTTP From
    [Documentation]    GET http://${addr}/ from namespace ${name}; returns the status code
    ...                or 0 when the connection fails or times out.
    [Arguments]    ${name}    ${addr}
    ${code}=    Catenate    SEPARATOR=
    ...    import urllib.request,sys\n
    ...    try:\n
    ...    \ \ print(urllib.request.urlopen('http://${addr}/', timeout=3).status)\n
    ...    except Exception:\n
    ...    \ \ print(0)
    ${r}=    In NS    ${name}    python3    -c    ${code}
    ${status}=    Strip String    ${r.stdout}
    RETURN    ${status}

TCP Connects From
    [Arguments]    ${name}    ${addr}    ${port}
    ${code}=    Catenate    SEPARATOR=
    ...    import socket\n
    ...    s=socket.socket(); s.settimeout(3)\n
    ...    try:\n
    ...    \ \ s.connect(('${addr}', ${port})); print('open')\n
    ...    except Exception as e:\n
    ...    \ \ print('closed')
    ${r}=    In NS    ${name}    python3    -c    ${code}
    ${state}=    Strip String    ${r.stdout}
    RETURN    ${state}
