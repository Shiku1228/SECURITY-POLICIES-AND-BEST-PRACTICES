import json
import os
import random
from datetime import datetime

class ComplianceAuditor:
    def __init__(self):
        self.audit_history = []
        self.state_file = "audit_state.json"

    def splunk_mock_audit(self):
        print("Starting mock Splunk log analysis...")
        results = [
            {"event": "Failed login attempt", "severity": random.choice(["Low", "Medium", "High"])},
            {"event": "Unauthorized file access", "severity": random.choice(["Medium", "High", "Critical"])},
            {"event": "Firewall configuration change", "severity": "Info"}
        ]
        violations = [r for r in results if r["severity"] in ["High", "Critical"]]
        if violations:
            print(f"Splunk Audit found {len(violations)} high/critical violations.")
        else:
            print("Splunk Audit found no major violations.")
        return violations

    def openvas_mock_audit(self):
        print("Starting mock OpenVAS vulnerability scan...")
        results = [
            {"vulnerability": "Outdated SSH version", "cvss": round(random.uniform(3.0, 9.0), 1)},
            {"vulnerability": "Unpatched Apache Server", "cvss": round(random.uniform(5.0, 10.0), 1)},
            {"vulnerability": "Weak SSL Ciphers supported", "cvss": round(random.uniform(4.0, 7.0), 1)}
        ]
        violations = [r for r in results if r["cvss"] >= 7.0]
        if violations:
            print(f"OpenVAS Scan found {len(violations)} high severity vulnerabilities.")
        else:
            print("OpenVAS Scan found no major vulnerabilities.")
        return violations

    def conduct_audit(self):
        print("\n--- Conducting Compliance Audit ---")
        splunk_violations = self.splunk_mock_audit()
        openvas_violations = self.openvas_mock_audit()
        
        audit_record = {
            "timestamp": datetime.now().isoformat(),
            "splunk_violations": splunk_violations,
            "openvas_violations": openvas_violations,
            "total_violations": len(splunk_violations) + len(openvas_violations)
        }
        self.audit_history.append(audit_record)
        self.save_state()
        print(f"Audit completed and recorded. Total violations found: {audit_record['total_violations']}")
        return audit_record

    def generate_report(self):
        if not self.audit_history:
            print("No audit history found. Please conduct an audit first.")
            return

        latest = self.audit_history[-1]
        print("\n=== Compliance Audit Report ===")
        print(f"Date: {latest['timestamp']}")
        print(f"Total Violations: {latest['total_violations']}")
        
        if latest["splunk_violations"]:
            print("\nSplunk Log Violations:")
            for v in latest["splunk_violations"]:
                print(f" - {v['event']} (Severity: {v['severity']})")
                
        if latest["openvas_violations"]:
            print("\nOpenVAS Vulnerabilities:")
            for v in latest["openvas_violations"]:
                print(f" - {v['vulnerability']} (CVSS: {v['cvss']})")
                
        print("===============================\n")

    def suggest_improvements(self):
        if not self.audit_history:
            print("No audit history found. Please conduct an audit first.")
            return

        latest = self.audit_history[-1]
        print("\n--- Improvement Suggestions ---")
        if latest["total_violations"] == 0:
            print("Great job! No major violations found. Continue regular monitoring.")
            return

        suggestions = []
        for v in latest["splunk_violations"]:
            if "login" in v["event"].lower():
                suggestions.append("Implement account lockout policies after failed login attempts.")
            if "access" in v["event"].lower():
                suggestions.append("Review and tighten Role-Based Access Control (RBAC) permissions.")
                
        for v in latest["openvas_violations"]:
            if "outdated" in v["vulnerability"].lower() or "unpatched" in v["vulnerability"].lower():
                suggestions.append("Establish a regular patch management schedule.")
            if "ssl" in v["vulnerability"].lower() or "tls" in v["vulnerability"].lower():
                suggestions.append("Disable weak SSL/TLS ciphers and enforce modern protocols.")

        # Deduplicate suggestions
        suggestions = list(set(suggestions))
        
        for i, suggestion in enumerate(suggestions, 1):
            print(f"{i}. {suggestion}")
            
        print("-------------------------------\n")

    def save_state(self):
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.audit_history, f)
        except Exception as e:
            print(f"Error saving audit state: {e}")

    def load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    self.audit_history = json.load(f)
            except Exception as e:
                print(f"Error loading audit state: {e}")
