#!/usr/bin/env python3
import json
import sys

# Порог критичных находок
THRESHOLD = 50

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def count_semgrep_errors(semgrep_json):
    count = 0
    for finding in semgrep_json.get('results', []):
        if finding.get('extra', {}).get('severity') == 'ERROR':
            count += 1
    return count

def count_pip_audit_vulns(audit_json):
    count = 0
    for pkg in audit_json.get('vulnerabilities', []):
        count += len(pkg.get('vulns', []))
    return count

def count_gitleaks_leaks(gitleaks_json):
    return len(gitleaks_json.get('Leaks', []))

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: check_security_findings.py semgrep.json pip-audit.json gitleaks.json")
        sys.exit(1)

    semgrep_file, pip_file, gitleaks_file = sys.argv[1], sys.argv[2], sys.argv[3]
    semgrep_data = load_json(semgrep_file)
    pip_data = load_json(pip_file)
    gitleaks_data = load_json(gitleaks_file)

    errors = count_semgrep_errors(semgrep_data)
    vulns = count_pip_audit_vulns(pip_data)
    leaks = count_gitleaks_leaks(gitleaks_data)

    total = errors + vulns + leaks
    print(f"Semgrep errors: {errors}, pip-audit vulns: {vulns}, Gitleaks leaks: {leaks}")
    if total > THRESHOLD:
        print(f"CRITICAL: Total issues ({total}) exceed threshold ({THRESHOLD})")
        sys.exit(1)
    else:
        print("OK: issues within threshold")
        sys.exit(0)