from security_policies import SecurityPolicyManager
from security_controls import SecurityControlsManager
from compliance_audit import ComplianceAuditor
from incident_response import IncidentResponseManager

def main():
    policy_manager = SecurityPolicyManager()
    controls_manager = SecurityControlsManager()
    controls_manager.load_state()  # Load previous state
    
    auditor = ComplianceAuditor()
    auditor.load_state()

    incident_responder = IncidentResponseManager()
    incident_responder.load_state()

    while True:
        print("\nInteractive Security Program")
        print("1. Develop Security Policies")
        print("2. Implement Security Controls")
        print("3. Conduct Compliance Audits")
        print("4. Security Incident Response")
        print("5. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            policy_menu(policy_manager)
        elif choice == "2":
            controls_menu(controls_manager)
        elif choice == "3":
            audit_menu(auditor)
        elif choice == "4":
            incident_menu(incident_responder)
        elif choice == "5":
            break
        else:
            print("Invalid choice.")

def policy_menu(manager):
    while True:
        print("\nPolicy Development Menu")
        print("1. Define Objectives")
        print("2. Define Scope")
        print("3. Create Password Policy")
        print("4. Create Network Access Policy")
        print("5. Create Data Protection Policy")
        print("6. Check Regulatory Compliance")
        print("7. Validate Policies")
        print("8. Back to Main Menu")

        choice = input("Choose an option: ")

        if choice == "1":
            manager.define_objectives()
        elif choice == "2":
            manager.define_scope()
        elif choice == "3":
            manager.create_policy("password")
        elif choice == "4":
            manager.create_policy("network_access")
        elif choice == "5":
            manager.create_policy("data_protection")
        elif choice == "6":
            manager.check_compliance()
        elif choice == "7":
            manager.validate_policies()
        elif choice == "8":
            break
        else:
            print("Invalid choice.")

def controls_menu(manager):
    while True:
        print("\nSecurity Controls Menu")
        print("1. Configure Firewall Rules")
        print("2. Configure ACLs")
        print("3. Setup Encryption")
        print("4. Enforce RBAC")
        print("5. Validate Controls")
        print("6. Back to Main Menu")

        choice = input("Choose an option: ")

        if choice == "1":
            manager.configure_firewall()
        elif choice == "2":
            manager.configure_acls()
        elif choice == "3":
            manager.setup_encryption()
        elif choice == "4":
            manager.enforce_rbac()
        elif choice == "5":
            manager.validate_controls()
        elif choice == "6":
            break
        else:
            print("Invalid choice.")

def audit_menu(auditor):
    while True:
        print("\nCompliance Audit Menu")
        print("1. Conduct Audit (Splunk/OpenVAS Simulation)")
        print("2. Generate Audit Report")
        print("3. View Improvement Suggestions")
        print("4. Back to Main Menu")

        choice = input("Choose an option: ")

        if choice == "1":
            auditor.conduct_audit()
        elif choice == "2":
            auditor.generate_report()
        elif choice == "3":
            auditor.suggest_improvements()
        elif choice == "4":
            break
        else:
            print("Invalid choice.")

def incident_menu(responder):
    while True:
        print("\nIncident Response Menu")
        print("1. Simulate Security Breach")
        print("2. Analyze Logs")
        print("3. Execute Automated Enforcement")
        print("4. View Incident History")
        print("5. Back to Main Menu")

        choice = input("Choose an option: ")

        if choice == "1":
            responder.simulate_breach()
        elif choice == "2":
            responder.analyze_logs()
        elif choice == "3":
            responder.automated_enforcement()
        elif choice == "4":
            responder.view_incident_history()
        elif choice == "5":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
