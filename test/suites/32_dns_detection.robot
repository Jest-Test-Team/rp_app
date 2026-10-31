*** Settings ***
Documentation     Detection quality of the deterministic DNS scorer at the default threshold,
...               measured on fixed samples (results/detection.json):
...               benign real-world names (false positives) vs. deterministic DGA-style and
...               DNS-tunnel-style names (detection). Samples are fixtures, so the numbers
...               are reproducible estimates — not guarantees for every network.
Resource          ../resources/common.resource
Test Tags         integration    dns    detection

*** Variables ***
${RP_DNS}         %{RP_DNS=${REPO}/target/debug/rp-dns}
${SAMPLES}        ${FIXTURES}/dns
${RESULTS}        ${CURDIR}/../results

*** Test Cases ***
False Positive Rate On Benign Names Is At Most 2 Percent
    ${r}=    Rate For    benign
    Should Be True    ${r['rate']} <= 0.02    msg=benign names flagged: ${r['examples']}

DNS Tunnel Detection Rate Is At Least 95 Percent
    ${r}=    Rate For    tunnel
    Should Be True    ${r['rate']} >= 0.95

DGA Detection Rate Is At Least 75 Percent
    ${r}=    Rate For    dga
    Should Be True    ${r['rate']} >= 0.75

*** Keywords ***
Rate For
    [Arguments]    ${sample}
    ${out}=    Run Ok    ${RP_DNS}    --config    /nonexistent    score    --file    ${SAMPLES}/${sample}.txt
    ${r}=    Evaluate    json.loads($out)    modules=json
    Log    ${sample}: ${r['flagged']}/${r['names']} flagged at threshold ${r['threshold']}    console=True
    Create Directory    ${RESULTS}
    ${line}=    Evaluate    json.dumps(dict(sample=$sample, **{k: v for k, v in $r.items() if k != 'examples'}))    modules=json
    Append To File    ${RESULTS}/detection.json    ${line}\n
    RETURN    ${r}
