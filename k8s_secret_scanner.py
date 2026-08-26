#!/usr/bin/env python3
"""CL4 — Kubernetes Secret Scanner: Detect secrets, analyze RBAC, audit network policies."""

import json
import re
import base64
import os
import sys
import yaml
import glob as globmod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


@dataclass
class Finding:
    severity: str
    category: str
    resource: str
    namespace: str
    message: str
    line_hint: str = ""

    def __str__(self):
        ns = f"{self.namespace}/" if self.namespace else ""
        return f"[{self.severity}] {self.category} | {ns}{self.resource}: {self.message}"


class KubernetesManifestParser:
    """Parse YAML/JSON K8s manifests (single or multi-document)."""

    @staticmethod
    def load_file(filepath: str) -> List[Dict[str, Any]]:
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        return KubernetesManifestParser.parse_content(content)

    @staticmethod
    def parse_content(content: str) -> List[Dict[str, Any]]:
        docs = []
        try:
            for doc in yaml.safe_load_all(content):
                if doc is not None and isinstance(doc, dict):
                    docs.append(doc)
        except yaml.YAMLError:
            try:
                doc = json.loads(content)
                if isinstance(doc, dict):
                    docs.append(doc)
                elif isinstance(doc, list):
                    docs.extend(d for d in doc if isinstance(d, dict))
            except json.JSONDecodeError:
                pass
        return docs

    @staticmethod
    def load_directory(dirpath: str) -> List[Dict[str, Any]]:
        all_docs = []
        patterns = ["*.yaml", "*.yml", "*.json"]
        files = []
        for pat in patterns:
            files.extend(globmod.glob(os.path.join(dirpath, "**", pat), recursive=True))
        for fp in sorted(set(files)):
            all_docs.extend(KubernetesManifestParser.load_file(fp))
        return all_docs


class SecretDetector:
    """Detect hardcoded secrets in Kubernetes manifests."""

    SENSITIVE_KEYS = [
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "api-key", "access_key", "access-key", "private_key", "private-key",
        "credential", "credentials", "auth_token", "auth-token",
        "connection_string", "connection-string", "database_url", "database-url",
        "secret_key", "secret-key", "encryption_key", "encryption-key",
        "client_secret", "client-secret", "jwt", "bearer",
    ]

    SENSITIVE_PATTERNS = [
        (re.compile(r"(?i)(AKIA[0-9A-Z]{16})", re.IGNORECASE), "AWS Access Key"),
        (re.compile(r"(?i)(ghp_[A-Za-z0-9]{36})", re.IGNORECASE), "GitHub PAT"),
        (re.compile(r"(?i)(sk-[A-Za-z0-9]{32,})", re.IGNORECASE), "OpenAI Key"),
        (re.compile(r"(?i)(xox[bpoas]-[A-Za-z0-9-]+)", re.IGNORECASE), "Slack Token"),
        (re.compile(r"(?i)(-----BEGIN (RSA |EC )?PRIVATE KEY-----)"), "Private Key"),
        (re.compile(r"(?i)mongodb(\+srv)?://[^\s]+"), "MongoDB Connection String"),
        (re.compile(r"(?i)postgres(ql)?://[^\s]+"), "PostgreSQL Connection String"),
        (re.compile(r"(?i)mysql://[^\s]+"), "MySQL Connection String"),
        (re.compile(r"(?i)redis://[^\s]+"), "Redis Connection String"),
    ]

    def scan(self, manifests: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        for doc in manifests:
            kind = doc.get("kind", "Unknown")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", "unnamed")
            ns = metadata.get("namespace", "")
            findings.extend(self._scan_dict(doc, kind, name, ns, path=""))
        return findings

    def _scan_dict(self, obj: Any, kind: str, name: str, ns: str, path: str) -> List[Finding]:
        findings: List[Finding] = []
        if isinstance(obj, dict):
            for key, val in obj.items():
                full_path = f"{path}.{key}" if path else key
                if isinstance(val, str):
                    findings.extend(self._check_value(key, val, kind, name, ns, full_path))
                elif isinstance(val, (dict, list)):
                    findings.extend(self._scan_dict(val, kind, name, ns, full_path))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                findings.extend(self._scan_dict(item, kind, name, ns, f"{path}[{i}]"))
        return findings

    def _check_value(self, key: str, value: str, kind: str, name: str, ns: str, path: str) -> List[Finding]:
        findings: List[Finding] = []
        key_lower = key.lower().replace("_", "").replace("-", "")

        for sensitive_key in self.SENSITIVE_KEYS:
            if sensitive_key.lower().replace("_", "").replace("-", "") in key_lower:
                if value and len(value) > 2:
                    findings.append(Finding(
                        severity="CRITICAL" if "private" in key_lower or "key" in key_lower else "HIGH",
                        category="Hardcoded Secret",
                        resource=f"{kind}/{name}",
                        namespace=ns,
                        message=f"Key '{key}' contains a plaintext secret",
                        line_hint=path,
                    ))
                    break

        for pattern, label in self.SENSITIVE_PATTERNS:
            if pattern.search(value):
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Exposed Credential",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    message=f"Value matches {label} pattern",
                    line_hint=path,
                ))

        if key_lower in ("data", "stringdata") and isinstance(obj := {}, dict) is False:
            pass

        if key.lower() == "data" and isinstance(value, dict):
            for data_key, data_val in value.items():
                if isinstance(data_val, str):
                    findings.extend(self._check_base64_value(data_key, data_val, kind, name, ns, path))

        if key.lower() == "stringdata" and isinstance(value, dict):
            for dk, dv in value.items():
                if isinstance(dv, str):
                    findings.extend(self._check_value(dk, dv, kind, name, ns, f"{path}.{dk}"))

        return findings

    def _check_base64_value(self, key: str, b64_val: str, kind: str, name: str, ns: str, path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            decoded = base64.b64decode(b64_val).decode("utf-8", errors="replace")
        except Exception:
            return findings

        key_lower = key.lower().replace("_", "").replace("-", "")
        for sensitive_key in self.SENSITIVE_KEYS:
            if sensitive_key.lower().replace("_", "").replace("-", "") in key_lower:
                findings.append(Finding(
                    severity="HIGH",
                    category="Base64 Secret",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    message=f"Base64-encoded secret in data.{key} (decoded length={len(decoded)})",
                    line_hint=f"{path}.{key}",
                ))
                break

        for pattern, label in self.SENSITIVE_PATTERNS:
            if pattern.search(decoded):
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Exposed Credential",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    message=f"Base64 data.{key} decodes to {label}",
                    line_hint=f"{path}.{key}",
                ))

        return findings


class RBACAnalyzer:
    """Analyze RBAC roles and cluster roles for privilege escalation."""

    DANGEROUS_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
    SENSITIVE_RESOURCES = {
        "secrets", "configmaps", "serviceaccounts", "roles", "rolebindings",
        "clusterroles", "clusterrolebindings", "pods", "nodes", "persistentvolumes",
    }
    ESCALATION_RESOURCES = {
        "roles", "clusterroles", "rolebindings", "clusterrolebindings",
        "serviceaccounts/token", "pods/exec", "pods/portforward",
    }
    WILDCARD_VERBS = {"*", "get", "list", "watch"}
    FULL_ACCESS_VERBS = {"*"}

    def analyze(self, manifests: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        for doc in manifests:
            kind = doc.get("kind", "")
            if kind in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding",
                        "ClusterRoleList", "RoleList"):
                findings.extend(self._analyze_rbac(doc))
        return findings

    def _analyze_rbac(self, doc: Dict) -> List[Finding]:
        findings: List[Finding] = []
        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unnamed")
        ns = metadata.get("namespace", "")

        rules = doc.get("rules", [])
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            verbs = set(rule.get("verbs", []))
            resources = set(rule.get("resources", []))
            api_groups = rule.get("apiGroups", [""])

            if "*" in verbs:
                findings.append(Finding(
                    severity="CRITICAL",
                    category="RBAC Over-permission",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    message=f"Wildcard verb '*' on resources {sorted(resources)}",
                ))

            if resources & self.ESCALATION_RESOURCES and verbs & self.DANGEROUS_VERBS:
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Privilege Escalation",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    message=f"Dangerous verbs {sorted(verbs & self.DANGEROUS_VERBS)} on escalation resources {sorted(resources & self.ESCALATION_RESOURCES)}",
                ))

            if "secrets" in resources and verbs & self.DANGEROUS_VERBS:
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Secret Access",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    message=f"Can modify secrets with verbs {sorted(verbs & self.DANGEROUS_VERBS)}",
                ))

            if "*" in resources:
                findings.append(Finding(
                    severity="HIGH",
                    category="Wildcard Resource",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    message=f"Wildcard resource '*' allows access to all resource types",
                ))

            if "nodes" in resources and verbs & {"get", "list", "watch"}:
                findings.append(Finding(
                    severity="MEDIUM",
                    category="Node Enumeration",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    message="Can enumerate cluster nodes",
                ))

            if "serviceaccounts" in resources and "get" in verbs:
                findings.append(Finding(
                    severity="HIGH",
                    category="SA Impersonation Risk",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    message="Can read service accounts (potential token theft)",
                ))

        return findings


class NetworkPolicyAuditor:
    """Audit Kubernetes NetworkPolicy resources."""

    def audit(self, manifests: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        policies = [d for d in manifests if d.get("kind") == "NetworkPolicy"]

        if not policies:
            findings.append(Finding(
                severity="HIGH",
                category="No Network Policies",
                resource="Cluster",
                namespace="(all)",
                message="No NetworkPolicy resources found — all pod-to-pod traffic is allowed",
            ))
            return findings

        for doc in policies:
            metadata = doc.get("metadata", {})
            name = metadata.get("name", "unnamed")
            ns = metadata.get("namespace", "")
            spec = doc.get("spec", {})
            findings.extend(self._audit_policy(doc, name, ns, spec))

        findings.extend(self._check_default_deny(policies))
        return findings

    def _audit_policy(self, doc: Dict, name: str, ns: str, spec: Dict) -> List[Finding]:
        findings: List[Finding] = []

        pod_selector = spec.get("podSelector", {})
        if not pod_selector or pod_selector == {}:
            findings.append(Finding(
                severity="MEDIUM",
                category="Broad Policy Scope",
                resource=f"NetworkPolicy/{name}",
                namespace=ns,
                message="Empty podSelector applies to all pods in namespace",
            ))

        ingress = spec.get("ingress", [])
        egress = spec.get("egress", [])

        if not ingress and not egress:
            findings.append(Finding(
                severity="MEDIUM",
                category="Empty Rules",
                resource=f"NetworkPolicy/{name}",
                namespace=ns,
                message="Policy has no ingress/egress rules (defaults to deny-all if policyTypes set)",
            ))

        for direction, rules in [("ingress", ingress), ("egress", egress)]:
            for i, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    continue
                from_rules = rule.get("from", []) if direction == "ingress" else []
                to_rules = rule.get("to", []) if direction == "egress" else []
                ports = rule.get("ports", [])

                if direction == "ingress" and not from_rules:
                    findings.append(Finding(
                        severity="HIGH",
                        category="Open Ingress",
                        resource=f"NetworkPolicy/{name}",
                        namespace=ns,
                        message=f"Ingress rule {i}: no 'from' constraint — accepts traffic from anywhere",
                    ))

                if direction == "egress" and not to_rules:
                    findings.append(Finding(
                        severity="HIGH",
                        category="Open Egress",
                        resource=f"NetworkPolicy/{name}",
                        namespace=ns,
                        message=f"Egress rule {i}: no 'to' constraint — allows traffic to anywhere",
                    ))

                if direction == "ingress":
                    for fr in from_rules:
                        if not isinstance(fr, dict):
                            continue
                        ip_block = fr.get("ipBlock", {})
                        if ip_block.get("cidr") in ("0.0.0.0/0", "::/0"):
                            findings.append(Finding(
                                severity="CRITICAL",
                                category="Public Ingress",
                                resource=f"NetworkPolicy/{name}",
                                namespace=ns,
                                message=f"Ingress rule {i}: ipBlock allows 0.0.0.0/0",
                            ))

                if direction == "egress":
                    for tr in to_rules:
                        if not isinstance(tr, dict):
                            continue
                        ip_block = tr.get("ipBlock", {})
                        if ip_block.get("cidr") in ("0.0.0.0/0", "::/0"):
                            excl = ip_block.get("except", [])
                            if not excl:
                                findings.append(Finding(
                                    severity="CRITICAL",
                                    category="Public Egress",
                                    resource=f"NetworkPolicy/{name}",
                                    namespace=ns,
                                    message=f"Egress rule {i}: ipBlock allows 0.0.0.0/0 without exceptions",
                                ))

        return findings

    def _check_default_deny(self, policies: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        ns_with_deny = set()
        for p in policies:
            ns = p.get("metadata", {}).get("namespace", "")
            spec = p.get("spec", {})
            pod_selector = spec.get("podSelector", {})
            policy_types = spec.get("policyTypes", [])
            ingress = spec.get("ingress", [])
            egress = spec.get("egress", [])

            if (not pod_selector or pod_selector == {}) and "Ingress" in policy_types and not ingress:
                ns_with_deny.add(ns)

        if ns_with_deny:
            findings.append(Finding(
                severity="LOW",
                category="Default Deny Found",
                resource="NetworkPolicy",
                namespace=", ".join(sorted(ns_with_deny)),
                message="Default deny ingress policy exists",
            ))

        return findings


class K8sSecretScanner:
    """Main scanner orchestrator."""

    def __init__(self):
        self.parser = KubernetesManifestParser()
        self.secret_detector = SecretDetector()
        self.rbac_analyzer = RBACAnalyzer()
        self.network_auditor = NetworkPolicyAuditor()

    def scan_file(self, filepath: str) -> List[Finding]:
        manifests = self.parser.load_file(filepath)
        return self._scan_manifests(manifests)

    def scan_directory(self, dirpath: str) -> List[Finding]:
        manifests = self.parser.load_directory(dirpath)
        return self._scan_manifests(manifests)

    def _scan_manifests(self, manifests: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self.secret_detector.scan(manifests))
        findings.extend(self.rbac_analyzer.analyze(manifests))
        findings.extend(self.network_auditor.audit(manifests))
        return findings

    def print_report(self, findings: List[Finding]):
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))

        print("\n" + "=" * 70)
        print("  CL4 — Kubernetes Secret Scanner Report")
        print("=" * 70)

        if not sorted_findings:
            print("\n  No findings detected.\n")
            return

        counts = {}
        for f in sorted_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        print("\n  Summary:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                print(f"    {sev}: {counts[sev]}")
        print(f"    TOTAL: {len(sorted_findings)}")
        print()

        for f in sorted_findings:
            print(f"  {f}")

        print("\n" + "=" * 70 + "\n")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="CL4 — Kubernetes Secret Scanner")
    parser.add_argument("target", help="File or directory to scan")
    args = parser.parse_args()

    scanner = K8sSecretScanner()
    target = args.target

    if os.path.isfile(target):
        findings = scanner.scan_file(target)
    elif os.path.isdir(target):
        findings = scanner.scan_directory(target)
    else:
        print(f"Error: {target} is not a valid file or directory", file=sys.stderr)
        sys.exit(1)

    scanner.print_report(findings)

    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    if critical > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
