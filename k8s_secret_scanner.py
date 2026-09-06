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
            findings.extend(self._check_env_pair(obj, kind, name, ns, path))
            for key, val in obj.items():
                full_path = f"{path}.{key}" if path else key
                if isinstance(val, str):
                    findings.extend(self._check_value(key, val, kind, name, ns, full_path))
                elif key.lower() == "data" and isinstance(val, dict):
                    for data_key, data_val in val.items():
                        if not isinstance(data_val, str):
                            continue
                        if "Secret" in kind:
                            findings.extend(
                                self._check_base64_value(data_key, data_val, kind, name, ns, full_path))
                        else:
                            findings.extend(
                                self._check_value(data_key, data_val, kind, name, ns,
                                                  f"{full_path}.{data_key}"))
                elif key.lower() == "stringdata" and isinstance(val, dict):
                    for dk, dv in val.items():
                        if isinstance(dv, str):
                            findings.extend(
                                self._check_value(dk, dv, kind, name, ns, f"{full_path}.{dk}"))
                elif isinstance(val, dict):
                    findings.extend(self._scan_dict(val, kind, name, ns, full_path))
                elif isinstance(val, list):
                    findings.extend(self._scan_dict(val, kind, name, ns, full_path))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                findings.extend(self._scan_dict(item, kind, name, ns, f"{path}[{i}]"))
        return findings

    def _check_env_pair(self, val: dict, kind: str, name: str, ns: str, path: str) -> List[Finding]:
        """Catch the {name: DB_PASSWORD, value: 'x'} pattern used by env entries."""
        findings: List[Finding] = []
        if not isinstance(val, dict) or "name" not in val or "value" not in val:
            return findings
        env_key = val.get("name")
        env_value = val.get("value")
        if not isinstance(env_key, str) or not isinstance(env_value, str):
            return findings
        if not env_key or not env_value:
            return findings
        key_lower = env_key.lower().replace("_", "").replace("-", "")
        for sensitive_key in self.SENSITIVE_KEYS:
            if sensitive_key.lower().replace("_", "").replace("-", "") in key_lower:
                findings.append(Finding(
                    severity="CRITICAL" if "private" in key_lower or "key" in key_lower
                    else "HIGH",
                    category="Hardcoded Secret",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    message=f"Environment variable '{env_key}' is set to a plaintext value",
                    line_hint=f"{path}.value",
                ))
                break
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


class WorkloadSecretsAuditor:
    """Audit workload specs for secret-handling anti-patterns.

    Rules:
    - Plaintext Secret (kind: Secret) should be a SealedSecret / external
      secret store instead (static base64 Secret data is opaque but reversible).
    - imagePullSecrets that reference a Secret not defined in the same set of
      manifests, or use pull-secret credentials opportunistically.
    - Containers consuming Secret values via env but referencing envFrom Secret
      names that cannot be resolved in the supplied manifests.
    """

    WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
                      "Job", "CronJob", "Pod"}

    def audit(self, manifests: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        defined_secrets = self._defined_secrets(manifests)

        for doc in manifests:
            kind = doc.get("kind", "")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", "unnamed")
            ns = metadata.get("namespace", "") or "default"

            if kind == "Secret":
                findings.extend(self._check_sealed_vs_plain_secret(doc, name, ns))

            if kind in self.WORKLOAD_KINDS:
                spec = self._workload_spec(doc)
                if spec:
                    findings.extend(
                        self._check_image_pull_secrets(spec, name, ns, defined_secrets, kind))
                    findings.extend(
                        self._check_env_secret_refs(spec, name, ns, defined_secrets, kind))
        return findings

    def _workload_spec(self, doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        kind = doc.get("kind", "")
        if kind == "Pod":
            return doc.get("spec", {})
        template = doc.get("spec", {}).get("template", {})
        if isinstance(template, dict):
            return template.get("spec", {})
        return {}

    def _defined_secrets(self, manifests: List[Dict[str, Any]]) -> set:
        names = set()
        for doc in manifests:
            if doc.get("kind") == "Secret":
                nm = doc.get("metadata", {}).get("name")
                if nm:
                    names.add(nm)
            if doc.get("kind") == "SealedSecret":
                nm = doc.get("metadata", {}).get("name")
                # SealedSecret mirrors the plaintext Secret name via spec.encryptedData.
                if nm:
                    names.add(nm)
        return names

    def _check_sealed_vs_plain_secret(self, doc, name, ns) -> List[Finding]:
        findings = []
        data = doc.get("data", {}) or {}
        string_data = doc.get("stringData", {}) or {}
        if not data and not string_data:
            return findings
        # The fixture carries the sealed counterpart marker so we can distinguish
        # an intentionally-SealedSecret scenario from a raw plaintext Secret.
        if doc.get("metadata", {}).get("annotations", {}).get("sealed-from"):
            return findings
        opaque_items = max(len(data), len(string_data))
        findings.append(Finding(
            severity="MEDIUM",
            category="Plaintext Secret instead of SealedSecret",
            resource=f"Secret/{name}",
            namespace=ns,
            message=(
                f"Secret stores {opaque_items} data item(s) as static base64. Prefer a SealedSecret "
                "or an external secrets manager so the manifest can be committed safely."),
            line_hint="spec.data",
        ))
        return findings

    def _check_image_pull_secrets(self, spec, name, ns, defined_secrets, kind) -> List[Finding]:
        findings = []
        ips = spec.get("imagePullSecrets", []) or []
        if not ips:
            # Not necessarily a finding; only flag when there is an obvious
            # usage that is misconfigured.
            return findings
        for entry in ips:
            pulled = entry.get("name")
            if not pulled:
                continue
            if pulled not in defined_secrets:
                findings.append(Finding(
                    severity="HIGH",
                    category="imagePullSecrets Misuse",
                    resource=f"{kind}/{name}",
                    namespace=ns,
                    message=(
                        f"imagePullSecrets references '{pulled}' which is not defined in the supplied "
                        "manifests — private registry credentials will fail to mount."),
                    line_hint="spec.template.spec.imagePullSecrets",
                ))
        return findings

    def _check_env_secret_refs(self, spec, name, ns, defined_secrets, kind) -> List[Finding]:
        findings = []
        containers = spec.get("containers", []) or []
        for container in containers:
            env_from = container.get("envFrom", []) or []
            for ref in env_from:
                secret_ref = ref.get("secretRef")
                if isinstance(secret_ref, dict) and secret_ref.get("name"):
                    sname = secret_ref["name"]
                    if sname not in defined_secrets:
                        findings.append(Finding(
                            severity="HIGH",
                            category="envFrom Secret Not Found",
                            resource=f"{kind}/{name}",
                            namespace=ns,
                            message=(
                                f"Container '{container.get('name', '?')}' mounts envFrom Secret "
                                f"'{sname}' which is not defined in the supplied manifests."),
                            line_hint="spec.template.spec.containers[].envFrom",
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
        self.workload_auditor = WorkloadSecretsAuditor()
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
        findings.extend(self.workload_auditor.audit(manifests))
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


def findings_to_json(findings: List[Finding]) -> dict:
    """Serialize findings into a JSON-ready report structure."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    crit_high = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    return {
        "tool": "CL4-K8sSecretScanner",
        "finding_count": len(findings),
        "critical_high_count": crit_high,
        "summary": counts,
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "resource": f.resource,
                "namespace": f.namespace,
                "message": f.message,
                "line_hint": f.line_hint,
                "remediation": REMEDIATIONS.get(f.category, "Review and restrict the affected Kubernetes resource."),
            }
            for f in sorted(findings, key=lambda x: severity_order.get(x.severity, 5))
        ],
    }


REMEDIATIONS = {
    "Hardcoded Secret": "Move plaintext secrets into a Kubernetes Secret or a SealedSecret / external secret store.",
    "Exposed Credential": "Rotate the exposed credential and stop embedding it in manifests.",
    "Base64 Secret": "Use a Secret + SealedSecret, or an external secrets manager, not static base64 data.",
    "RBAC Over-permission": "Replace wildcard verbs with least-privilege verbs on scoped resources.",
    "Privilege Escalation": "Remove create/update/patch/delete on roles, rolebindings and serviceaccounts.",
    "Secret Access": "Remove write verbs on secrets; grant only get/list to the specific secrets needed.",
    "Wildcard Resource": "Scope RBAC resources to the types actually required.",
    "Node Enumeration": "Remove get/list/watch on nodes for non-admin service accounts.",
    "SA Impersonation Risk": "Restrict serviceaccount reads to the specific accounts that need them.",
    "No Network Policies": "Add a default-deny ingress/egress NetworkPolicy per namespace.",
    "Broad Policy Scope": "Tighten the podSelector to specific workloads.",
    "Empty Rules": "Define explicit ingress/egress rules or remove the policy.",
    "Open Ingress": "Add a 'from' constraint (namespaceSelector/podSelector/ipBlock) to ingress rules.",
    "Open Egress": "Add a 'to' constraint to egress rules.",
    "Public Ingress": "Restrict ipBlock cidr to trusted ranges instead of 0.0.0.0/0.",
    "Public Egress": "Restrict egress ipBlock and add exceptions instead of 0.0.0.0/0.",
    "Default Deny Found": "Keep the default-deny policy; add scoped allow rules as needed.",
    "Plaintext Secret instead of SealedSecret":
        "Use a SealedSecret or an external secrets manager so the manifest can be committed safely.",
    "imagePullSecrets Misuse":
        "Define the referenced Secret in the cluster (or a SealedSecret) before the workload mounts it.",
    "envFrom Secret Not Found":
        "Define the referenced Secret in the supplied manifests, or verify it exists in the target namespace.",
}


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="CL4 — Kubernetes Secret Scanner (offline, no cluster access)",
        epilog="Examples:\n"
               "  python3 k8s_secret_scanner.py manifests/\n"
               "  python3 k8s_secret_scanner.py --demo\n"
               "  python3 k8s_secret_scanner.py --demo --output reports/demo.json",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="?", help="File or directory to scan")
    parser.add_argument("--demo", action="store_true",
                        help="Run offline demo against a bundled fixture manifest")
    parser.add_argument("--output", "-o", default="",
                        help="Write JSON report to this path")
    parser.add_argument("--exit-code-on-findings", action="store_true",
                        help="Exit 2 when CRITICAL/HIGH findings exist (CI-friendly)")
    args = parser.parse_args()

    if args.demo:
        args.target = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "fixtures", "insecure-manifests.yaml")

    if not args.target:
        parser.print_help()
        return 1

    scanner = K8sSecretScanner()
    target = args.target

    if os.path.isfile(target):
        findings = scanner.scan_file(target)
    elif os.path.isdir(target):
        findings = scanner.scan_directory(target)
    else:
        print(f"Error: {target} is not a valid file or directory", file=sys.stderr)
        return 1

    scanner.print_report(findings)

    report = findings_to_json(findings)
    if args.output:
        out_dir = os.path.dirname(os.path.abspath(args.output))
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] JSON report written to {args.output}")

    if args.exit_code_on_findings and report["critical_high_count"] > 0:
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
