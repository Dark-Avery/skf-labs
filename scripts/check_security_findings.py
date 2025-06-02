#!/usr/bin/env python3
import json
import sys

THRESHOLD = 75

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def count_sarif_findings(sarif_json):
    return len(sarif_json.get('runs', [{}])[0].get('results', []))

def count_pip_audit_vulns(audit_json):
    count = 0
    for dep in audit_json.get("dependencies", []):
        count += len(dep.get("vulns", []))
    return count

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: check_security_findings.py semgrep.sarif pip-audit.json gitleaks.sarif")
        sys.exit(1)

    semgrep_file, pip_file, gitleaks_file = sys.argv[1], sys.argv[2], sys.argv[3]
    semgrep_data = load_json(semgrep_file)
    pip_data = load_json(pip_file)
    gitleaks_data = load_json(gitleaks_file)

    semgrep_findings = count_sarif_findings(semgrep_data)
    pip_vulns = count_pip_audit_vulns(pip_data)
    gitleaks_leaks = count_sarif_findings(gitleaks_data)

    total = semgrep_findings + pip_vulns + gitleaks_leaks
    print(f"Semgrep findings: {semgrep_findings}, pip-audit vulns: {pip_vulns}, Gitleaks leaks: {gitleaks_leaks}")
    if total > THRESHOLD:
        print(f"CRITICAL: Total issues ({total}) exceed threshold ({THRESHOLD})")
        sys.exit(1)
    else:
        print("OK: issues within threshold")
        sys.exit(0)
