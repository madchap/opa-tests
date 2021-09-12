package vulnpolicy

default allow = false

allow = true {
    count(violation) == 0
}

# Is the vuln a critical?
violation[vuln.id] {
    vuln := input.matches[_].vulnerability
    vuln.severity == "Critical"
}

# Simple get the CVSS score from related vulnerabilities
violation[vuln.id] {
   vuln := input.matches[_].relatedVulnerabilities[_]
   vuln.cvss[1].metrics.baseScore > 9.0
}

# If a related vuln scores high, flag.
# vulns_that_relate_to_more_severe_vulns[matches] {
#     matches := input.matches[_]
#     matches[_].vulnerability.severity == "Critical"
#     matches[_].relatedVulnerabilities[_].severity == "Critical"
# }
