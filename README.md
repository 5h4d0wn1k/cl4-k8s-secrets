# CL4 — Kubernetes Secret Scanner

Detect hardcoded secrets, analyze RBAC policies, and audit network policies in Kubernetes manifests.

## Overview

This project implements a static analysis tool that:
- Parses multi-document YAML/JSON Kubernetes manifests
- Detects hardcoded secrets (plaintext and Base64-encoded)
- Identifies known credential patterns (AWS keys, GitHub PATs, DB URIs)
- Analyzes RBAC roles for privilege escalation risks
- Audits NetworkPolicy resources for misconfigurations

## Features

- **Manifest Parsing**: Load single files or entire directories (YAML + JSON)
- **Secret Detection**: Plaintext, Base64-encoded, and regex-matched credentials
- **RBAC Analysis**: Wildcard verbs, escalation paths, secret access
- **Network Policy Audit**: Open ingress/egress, public CIDR blocks, default deny
- **Severity Ranking**: CRITICAL through LOW with summary report

## Usage

```bash
# Offline demo (no cluster access) — audit bundled fixture manifests
python3 k8s_secret_scanner.py --demo

# Scan a single manifest
python3 k8s_secret_scanner.py deployment.yaml

# Scan a directory of manifests
python3 k8s_secret_scanner.py ./k8s-manifests/

# JSON report + CI exit code
python3 k8s_secret_scanner.py --demo --output reports/demo.json --exit-code-on-findings
```

## Requirements

- Python 3.7+
- PyYAML (`pip install pyyaml`) — only needed for YAML manifests; JSON manifests are parsed with the standard library.

## Exit Codes

- `0` — completed cleanly (or demo finished without explicit CRITICAL/HIGH gate)
- `1` — error (missing target, unreadable/bad file)
- `2` — CRITICAL/HIGH findings present with `--exit-code-on-findings`

## Live Lab Test Plan

Runs entirely offline against `fixtures/insecure-manifests.yaml` — no cluster, no kubectl, no cloud.

1. **Demo**: `python3 k8s_secret_scanner.py --demo` — expect CRITICAL/HIGH/MEDIUM findings for hardcoded secrets, Base64 credentials, RBAC wildcard/severification, privilege escalation, public ingress, `imagePullSecrets Misuse` (undefined registry secret), `envFrom Secret Not Found`, and `Plaintext Secret instead of SealedSecret`. Exit `0`.
2. **JSON report**: `python3 k8s_secret_scanner.py --demo --output reports/demo.json` — verify the report has `finding_count > 0`, `critical_high_count > 0`, and per-finding `severity`, `category`, `message`, `remediation`.
3. **CI exit code**: `python3 k8s_secret_scanner.py --demo --exit-code-on-findings; echo $?` — expect `2`.
4. **Unit tests**: `python3 -m unittest discover -s tests -v` — all pass (exercises SecretDetector, RBACAnalyzer, NetworkPolicyAuditor, WorkloadSecretsAuditor, and the full fixture).
5. **Live (optional)**: point the tool at any manifest file/directory you are authorized to review. Static only — never touches a cluster.

## Metrics

- Detection engines: SecretDetector (hardcoded + Base64 + regex credentials), WorkloadSecretsAuditor (SealedSecret-instead-of, imagePullSecrets misuse, envFrom Secret existence), RBACAnalyzer (over-permission, privilege escalation, secret access, node enum, SA impersonation), NetworkPolicyAuditor (default deny, open ingress/egress, public CIDR)
- Rules exercised offline (real code paths): Hardcoded Secret, Exposed Credential, Base64 Secret, Plaintext Secret instead of SealedSecret, imagePullSecrets Misuse, envFrom Secret Not Found, RBAC Over-permission, Secret Access, Privilege Escalation, Wildcard Resource, Node Enumeration, SA Impersonation Risk, No Network Policies, Public Ingress, Public Egress, Open Ingress/Egress, Broad Policy Scope, Empty Rules, Default Deny Found
- Every finding carries `severity`, `category`, `resource`, `namespace`, `message`, and a `remediation` string
- Exit-code contract: `0` clean / `1` error / `2` findings (with `--exit-code-on-findings`)
- `--demo` and the fixture ruleset run 100% offline; YAML parsing is the only optional dependency (PyYAML)

## Legal Disclaimer

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the cluster owner before using this tool
- Unauthorized access to Kubernetes clusters is illegal under federal and state laws
- This tool should ONLY be used on clusters you own or have written authorization to audit

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own Kubernetes clusters
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
