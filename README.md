> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# CL4 — Kubernetes Secret Scanner

**Kubernetes secrets posture checker** by **5h4d0wn1k** for **cluster
configuration auditing** and DevSecOps: static analysis of YAML/JSON manifests
that detects hardcoded secrets, over-privileged RBAC roles, weak
NetworkPolicies and workload secret misconfigurations — no cluster access
required. Severity-ranked findings with a CI-ready exit-code gate.

## Why audit K8s manifests statically

Kubernetes secrets don't only leak through etcd — they leak through committed
manifests, permissive RBAC and empty network policies. This scanner brings the
audit to the code: it parses multi-document manifests and reports hardcoded
credentials, Base64-obscured secrets, RBAC over-permission and privilege
escalation paths, publicly-open ingress/egress, `imagePullSecrets` misuse and
`envFrom` references to undefined secrets. Because it is a static analyzer, a
full posture review runs completely offline against bundled fixtures — ideal
for education, CI gates and pre-commit reviews of infrastructure you own or
are authorized to audit. See [ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md).

## Features

- **Manifest parsing** — single file or whole directory, YAML and JSON
  multi-document support (`KubernetesManifestParser`).
- **Secret detection** — plaintext and Base64-encoded secrets plus
  regex-matched credentials (AWS keys, GitHub PATs, DB URIs)
  (`SecretDetector`).
- **Workload secrets audit** — catches plaintext Secret instead of
  SealedSecret, `imagePullSecrets` misuse and `envFrom` references to
  undeclared Secrets (`WorkloadSecretsAuditor`).
- **RBAC analysis** — wildcard verbs, privilege-escalation paths, secret
  access, node enumeration and service-account impersonation risks
  (`RBACAnalyzer`).
- **NetworkPolicy audit** — missing default deny, open ingress/egress, public
  CIDRs, broad scope and empty rules (`NetworkPolicyAuditor`).
- **Severity ranking** — CRITICAL → LOW with `severity`, `category`,
  `resource`, `namespace`, `message` and `remediation` per finding.
- **CI exit codes** — `0` clean / `1` error / `2` findings gate with
  `--exit-code-on-findings`.

## Quickstart

Prerequisite: Python 3.7+ and PyYAML (`pip install pyyaml`) for YAML
manifests; JSON is parsed with the standard library.

```bash
# Offline demo (no cluster access) — audit bundled fixture manifests
python3 k8s_secret_scanner.py --demo

# Scan a single manifest
python3 k8s_secret_scanner.py deployment.yaml

# Scan a directory of manifests
python3 k8s_secret_scanner.py ./k8s-manifests/

# JSON report + CI exit code
python3 k8s_secret_scanner.py --demo --output reports/demo.json --exit-code-on-findings
echo $?   # 2 when CRITICAL/HIGH findings are present

# Run the test suite (17 deterministic offline tests)
python3 -m unittest discover -s tests
```

## Exit codes

| Code | Meaning                                                    |
|------|------------------------------------------------------------|
| `0`  | Completed cleanly (or demo without an explicit gate)       |
| `1`  | Error — missing target, unreadable/ill-formed file         |
| `2`  | CRITICAL/HIGH findings with `--exit-code-on-findings`      |

## Project structure

```
k8s_secret_scanner.py        # scanner engine: parsers, detectors, auditors, CLI
fixtures/insecure-manifests.yaml  # offline demo fixture with known findings
tests/test_k8s_secret_scanner.py  # unittest coverage of all engines
ETHICS.md                    # educational-use policy (read first)
SCOPE.md                     # scope and target authorization rules
```

## Documentation

- [ETHICS.md](ETHICS.md) — acceptable and prohibited use.
- [SCOPE.md](SCOPE.md) — authorized target scope.
- [SECURITY.md](SECURITY.md) — responsible disclosure.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide.

## Contributing

New detector patterns, RBAC escalation rules and fixture cases are welcome.
Open an issue or PR against the default branch; keep contributions scoped to
educational and authorized-use tooling.

## License

MIT — full legal shield in [LICENSE](LICENSE). Static, educational and
authorization-required software for auditing Kubernetes configurations you own
or are explicitly permitted to review.