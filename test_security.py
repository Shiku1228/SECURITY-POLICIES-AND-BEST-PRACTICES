import unittest
from security_policies import SecurityPolicyManager, PasswordPolicy
from security_controls import SecurityControlsManager
from compliance_audit import ComplianceAuditor
from incident_response import IncidentResponseManager

class TestSecuritySystem(unittest.TestCase):

    def test_policy_manager(self):
        pm = SecurityPolicyManager()
        pm.objectives = ["Protect data"]
        pm.scope = "All internal systems"
        
        # Test validation logic
        self.assertFalse(pm.validate_policies())
        
        # Add mock policies
        pw_policy = PasswordPolicy()
        pw_policy.details = {"min_length": "12", "complexity": "High", "expiration": "90"}
        pm.policies["password"] = pw_policy
        
        self.assertTrue(pm.objectives)
        self.assertIsNotNone(pm.policies["password"])

    def test_controls_manager(self):
        cm = SecurityControlsManager()
        cm.firewall_rules.append("allow 10.0.0.0/8 any 443")
        cm.encryption = {"at_rest": "AES-256", "in_transit": "TLS 1.3"}
        
        # Validate incomplete state
        self.assertFalse(cm.validate_controls())
        
        # Complete the required fields for validation
        cm.acls.append("db_read admin")
        cm.rbac["roles"] = {"admin": ["all"]}
        
        self.assertTrue(cm.validate_controls())

    def test_compliance_auditor(self):
        ca = ComplianceAuditor()
        # Ensure audits return lists of violations
        splunk_violations = ca.splunk_mock_audit()
        openvas_violations = ca.openvas_mock_audit()
        
        self.assertIsInstance(splunk_violations, list)
        self.assertIsInstance(openvas_violations, list)
        
        audit_record = ca.conduct_audit()
        self.assertEqual(len(ca.audit_history), 1)
        self.assertIn("total_violations", audit_record)

    def test_incident_response(self):
        irm = IncidentResponseManager()
        incident = irm.simulate_breach()
        
        self.assertEqual(incident["status"], "Active")
        self.assertEqual(len(irm.incident_log), 1)
        
        # Analyze advances state
        irm.analyze_logs()
        self.assertEqual(irm.incident_log[0]["status"], "Analyzed")
        
        # Enforcement advances state
        irm.automated_enforcement()
        self.assertEqual(irm.incident_log[0]["status"], "Resolved")

if __name__ == "__main__":
    unittest.main()
