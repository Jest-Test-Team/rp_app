*** Settings ***
Documentation     Unit tests: every crate's Rust unit tests must pass and must exist.
Resource          ../resources/common.resource
Test Tags         unit
Test Template     Crate Unit Tests Pass

*** Test Cases ***    CRATE         MIN_TESTS
rp-schema             rp-schema     2
rp-core               rp-core       55
rpctl                 rpctl         2
rp-probe              rp-probe      7
rp-dns                rp-dns        13
rp-http               rp-http       2
rp-policy             rp-policy     14
rp-agent              rp-agent      8
rp-mcp                rp-mcp        3

*** Keywords ***
Crate Unit Tests Pass
    [Arguments]    ${crate}    ${min_tests}
    ${r}=    Run Expecting    0    cargo    test    -p    ${crate}    --    --test-threads\=1
    ${counts}=    Get Regexp Matches    ${r.stdout}    test result: ok\\. (\\d+) passed    1
    ${total}=    Evaluate    sum(int(c) for c in $counts)
    Should Be True    ${total} >= ${min_tests}
    ...    ${crate} ran ${total} tests, expected at least ${min_tests}
    Should Not Contain    ${r.stdout}    FAILED
