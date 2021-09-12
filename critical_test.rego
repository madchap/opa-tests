package vulnpolicy

test_vuln_critical {
    not allow with input as {"matches": [{"vulnerability": {"id": "CVE-XXX-YYYY", "severity": "Critical"}}]}
}

test_vuln_negligeable {
    allow with input as {"matches": [{"vulnerability": {"id": "CVE-XXX-YYYY", "severity": "Negligeable"}}]}
    
}

# witness test
test_ok {
    true
}
