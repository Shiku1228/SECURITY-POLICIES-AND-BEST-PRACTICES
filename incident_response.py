import json
import os
import random
import time
from datetime import datetime

class IncidentResponseManager:
    def __init__(self):
        self.incident_log = []
        self.state_file = "incident_state.json"
        self.breach_scenarios = [
            {"type": "Ransomware Attack", "severity": "Critical", "description": "Rapid file encryption detected on shared drives."},
            {"type": "Data Exfiltration", "severity": "High", "description": "Large outbound data transfer to unknown IP addresses detected."},
            {"type": "DDoS Attack", "severity": "Medium", "description": "High volume of traffic overwhelming external interfaces."},
            {"type": "Phishing Compromise", "severity": "High", "description": "Multiple user accounts compromised via malicious email links."}
        ]

    def simulate_breach(self):
        print("\n--- Simulating Security Breach ---")
        scenario = random.choice(self.breach_scenarios)
        
        print("ATTENTION! Abnormal activity detected...")
        time.sleep(1)
        print(f"Alert Type: {scenario['type']}")
        print(f"Severity: {scenario['severity']}")
        print(f"Description: {scenario['description']}")
        
        incident = {
            "id": f"INC-{random.randint(1000, 9999)}",
            "timestamp": datetime.now().isoformat(),
            "scenario": scenario,
            "status": "Active"
        }
        self.incident_log.append(incident)
        self.save_state()
        print(f"\nIncident {incident['id']} logged and escalated to active status.")
        return incident

    def analyze_logs(self):
        print("\n--- Log Analysis ---")
        active_incidents = [inc for inc in self.incident_log if inc["status"] == "Active"]
        
        if not active_incidents:
            print("No active incidents to analyze.")
            return

        for incident in active_incidents:
            print(f"Analyzing Incident {incident['id']} ({incident['scenario']['type']})...")
            time.sleep(1)
            print("Identifying indicators of compromise (IoCs)...")
            time.sleep(1)
            print("Tracing lateral movement...")
            time.sleep(1)
            print(f"Analysis complete for {incident['id']}. Preparing enforcement mechanisms.")
            incident["status"] = "Analyzed"
            
        self.save_state()

    def automated_enforcement(self):
        print("\n--- Automated Enforcement ---")
        analyzed_incidents = [inc for inc in self.incident_log if inc["status"] == "Analyzed"]
        
        if not analyzed_incidents:
            print("No analyzed incidents awaiting enforcement.")
            return
            
        for incident in analyzed_incidents:
            print(f"Executing automated response for {incident['id']}...")
            time.sleep(1)
            scenario_type = incident['scenario']['type']
            
            if scenario_type == "Ransomware Attack":
                print(" -> Isolating infected subnet.")
                print(" -> Revoking SMB share write access globally.")
            elif scenario_type == "Data Exfiltration":
                print(" -> Blocking external IP addresses at perimeter firewall.")
                print(" -> Terminating offending user sessions.")
            elif scenario_type == "DDoS Attack":
                print(" -> Rerouting traffic through scrubbing center.")
                print(" -> Applying rate limiting rules.")
            elif scenario_type == "Phishing Compromise":
                print(" -> Forcing password resets for affected users.")
                print(" -> Purging malicious emails from Exchange server.")
                
            print(f"Enforcement complete. Incident {incident['id']} contained and resolved.")
            incident["status"] = "Resolved"
            
        self.save_state()

    def view_incident_history(self):
        print("\n=== Incident History ===")
        if not self.incident_log:
            print("No incidents recorded.")
            return
            
        for inc in self.incident_log:
            print(f"[{inc['timestamp']}] {inc['id']} - {inc['scenario']['type']} - Status: {inc['status']}")
        print("========================")

    def save_state(self):
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.incident_log, f)
        except Exception as e:
            print(f"Error saving incident state: {e}")

    def load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    self.incident_log = json.load(f)
            except Exception as e:
                print(f"Error loading incident state: {e}")
