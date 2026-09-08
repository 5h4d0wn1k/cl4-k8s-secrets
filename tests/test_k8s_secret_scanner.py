import base64
import os
import unittest
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import k8s_secret_scanner as scanner_mod

FIXTURE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "fixtures", "insecure-manifests.yaml")

SAMPLE = """
apiVersion: v1
kind: Secret
metadata:
  name: test-secret
type: Opaque
data:
  password: %s
"""


class TestSecretDetector(unittest.TestCase):

    def setUp(self):
        self.detector = scanner_mod.SecretDetector()

    def test_finds_hardcoded_plaintext_secret(self):
        doc = {"kind": "Deployment",
               "metadata": {"name": "d", "namespace": "ns"},
               "spec": {"template": {"spec": {"containers": [
                   {"name": "c", "env": [{"name": "DB_PASSWORD",
                                          "value": "HardcodedDbPass123!"}]}]}}}}
        findings = self.detector.scan([doc])
        cats = [f.category for f in findings]
        self.assertIn("Hardcoded Secret", cats)

    def test_finds_base64_aws_key(self):
        b64 = base64.b64encode(b"AKIA" + b"ZXCRGB2I4YZSEC2HEX").decode()
        doc = {"kind": "Secret", "metadata": {"name": "s", "namespace": "ns"},
               "type": "Opaque", "data": {"api_key": b64}}
        findings = self.detector.scan([doc])
        cats = [f.category for f in findings]
        self.assertIn("Exposed Credential", cats)
        self.assertIn("Base64 Secret", cats)

    def test_finds_connection_string(self):
        doc = {"kind": "ConfigMap", "metadata": {"name": "c", "namespace": "ns"},
               "data": {"database_url": "postgresql://admin:pass@db.example.com/appdb"}}
        findings = self.detector.scan([doc])
        cats = [f.category for f in findings]
        self.assertIn("Exposed Credential", cats)

    def test_clean_secret_no_findings(self):
        clean = base64.b64encode(b"just-some-normal-value").decode()
        doc = {"kind": "Secret", "metadata": {"name": "s", "namespace": "ns"},
               "type": "Opaque", "data": {"non_sensitive_file": clean}}
        findings = self.detector.scan([doc])
        self.assertEqual(findings, [])


class TestRBACAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = scanner_mod.RBACAnalyzer()

    def test_wildcard_verbs(self):
        doc = {"kind": "Role", "metadata": {"name": "r", "namespace": "ns"},
               "rules": [{"apiGroups": [""], "resources": ["*"], "verbs": ["*"]}]}
        findings = self.analyzer.analyze([doc])
        cats = [f.category for f in findings]
        self.assertIn("RBAC Over-permission", cats)
        self.assertIn("Wildcard Resource", cats)

    def test_secret_modification(self):
        doc = {"kind": "Role", "metadata": {"name": "r", "namespace": "ns"},
               "rules": [{"apiGroups": [""], "resources": ["secrets"],
                          "verbs": ["get", "create", "delete"]}]}
        findings = self.analyzer.analyze([doc])
        cats = [f.category for f in findings]
        self.assertIn("Secret Access", cats)

    def test_escalation_resources(self):
        doc = {"kind": "ClusterRole", "metadata": {"name": "cr"},
               "rules": [{"apiGroups": ["rbac.authorization.k8s.io"],
                          "resources": ["clusterrolebindings"],
                          "verbs": ["create", "patch"]}]}
        findings = self.analyzer.analyze([doc])
        cats = [f.category for f in findings]
        self.assertIn("Privilege Escalation", cats)


class TestNetworkPolicyAuditor(unittest.TestCase):

    def setUp(self):
        self.auditor = scanner_mod.NetworkPolicyAuditor()

    def test_no_policies_finding(self):
        findings = self.auditor.audit([])
        cats = [f.category for f in findings]
        self.assertIn("No Network Policies", cats)

    def test_open_ingress_public(self):
        doc = {"kind": "NetworkPolicy", "metadata": {"name": "np", "namespace": "ns"},
               "spec": {"podSelector": {}, "ingress": [
                   {"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}],
                    "ports": [{"port": 80}]}]}}
        findings = self.auditor.audit([doc])
        cats = [f.category for f in findings]
        self.assertIn("Public Ingress", cats)


class TestWorkloadSecretsAuditor(unittest.TestCase):

    def setUp(self):
        self.auditor = scanner_mod.WorkloadSecretsAuditor()

    def test_plaintext_secret_flags_sealedsecret_alternative(self):
        doc = {"kind": "Secret", "metadata": {"name": "s", "namespace": "ns"},
               "type": "Opaque",
               "data": {"k": base64.b64encode(b"value").decode()}}
        findings = self.auditor.audit([doc])
        cats = [f.category for f in findings]
        self.assertIn("Plaintext Secret instead of SealedSecret", cats)

    def test_sealedsecret_not_flagged_as_plaintext(self):
        doc = {"kind": "SealedSecret",
               "metadata": {"name": "s", "namespace": "ns"},
               "spec": {"encryptedData": {"k": "AgBy..."}}}
        findings = self.auditor.audit([doc])
        cats = [f.category for f in findings]
        self.assertNotIn("Plaintext Secret instead of SealedSecret", cats)

    def test_undefined_image_pull_secret_flagged(self):
        doc = {"kind": "Deployment", "metadata": {"name": "d", "namespace": "ns"},
               "spec": {"template": {"spec": {
                   "imagePullSecrets": [{"name": "missing-pull"}],
                   "containers": [{"name": "c", "image": "img"}]}}}}
        findings = self.auditor.audit([doc])
        cats = [f.category for f in findings]
        self.assertIn("imagePullSecrets Misuse", cats)

    def test_defined_image_pull_secret_not_flagged(self):
        manifest = [
            {"kind": "Secret", "metadata": {"name": "regcred", "namespace": "ns"},
             "type": "kubernetes.io/dockerconfigjson", "data": {"x": "e30="}},
            {"kind": "Deployment", "metadata": {"name": "d", "namespace": "ns"},
             "spec": {"template": {"spec": {
                 "imagePullSecrets": [{"name": "regcred"}],
                 "containers": [{"name": "c", "image": "img"}]}}}},
        ]
        findings = self.auditor.audit(manifest)
        cats = [f.category for f in findings]
        self.assertNotIn("imagePullSecrets Misuse", cats)

    def test_undefined_envfrom_secret_flagged(self):
        doc = {"kind": "Deployment", "metadata": {"name": "d", "namespace": "ns"},
               "spec": {"template": {"spec": {"containers": [
                   {"name": "c", "image": "img",
                    "envFrom": [{"secretRef": {"name": "no-such-secret"}}]}]}}}}
        findings = self.auditor.audit([doc])
        cats = [f.category for f in findings]
        self.assertIn("envFrom Secret Not Found", cats)


class TestFullScannerFixture(unittest.TestCase):

    def test_fixture_findings(self):
        scanner = scanner_mod.K8sSecretScanner()
        findings = scanner.scan_file(FIXTURE)
        self.assertGreater(len(findings), 0)
        cats = {f.category for f in findings}
        self.assertTrue(cats & {
            "Hardcoded Secret", "Exposed Credential", "Base64 Secret",
            "RBAC Over-permission", "Privilege Escalation", "Public Ingress"})

    def test_fixture_workload_secret_rules_fire(self):
        scanner = scanner_mod.K8sSecretScanner()
        findings = scanner.scan_file(FIXTURE)
        cats = {f.category for f in findings}
        self.assertTrue({"imagePullSecrets Misuse", "envFrom Secret Not Found",
                         "Plaintext Secret instead of SealedSecret"} <= cats)

    def test_report_json_structure(self):
        scanner = scanner_mod.K8sSecretScanner()
        findings = scanner.scan_file(FIXTURE)
        report = scanner_mod.findings_to_json(findings)
        self.assertEqual(report["finding_count"], len(findings))
        self.assertGreater(report["critical_high_count"], 0)
        for f in report["findings"]:
            self.assertIn("remediation", f)
            self.assertIn("severity", f)


if __name__ == "__main__":
    unittest.main()