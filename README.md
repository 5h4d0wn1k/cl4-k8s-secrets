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
# Scan a single manifest
python3 k8s_secret_scanner.py deployment.yaml

# Scan a directory of manifests
python3 k8s_secret_scanner.py ./k8s-manifests/
```

## Requirements

- Python 3.7+
- PyYAML (`pip install pyyaml`)

## Legal Disclaimer

**IMPORTANT: Read before use.**

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
