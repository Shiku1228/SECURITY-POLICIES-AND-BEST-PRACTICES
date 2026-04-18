import json
import os

class SecurityControlsManager:
    def __init__(self):
        self.firewall_rules = []
        self.acls = []
        self.encryption = {"at_rest": None, "in_transit": None}
        self.rbac = {"roles": {}, "users": {}}
        self.state_file = "security_controls_state.json"

    def load_state(self):
        if os.path.exists(self.state_file):
            with open(self.state_file, 'r') as f:
                data = json.load(f)
                self.firewall_rules = data.get("firewall_rules", [])
                self.acls = data.get("acls", [])
                self.encryption = data.get("encryption", {})
                self.rbac = data.get("rbac", {"roles": {}, "users": {}})

    def save_state(self):
        data = {
            "firewall_rules": self.firewall_rules,
            "acls": self.acls,
            "encryption": self.encryption,
            "rbac": self.rbac
        }
        with open(self.state_file, 'w') as f:
            json.dump(data, f, indent=4)

    def configure_firewall(self):
        print("Configuring Firewall Rules:")
        print("Enter rules one by one. Format: action source_ip dest_ip port (e.g., allow 192.168.1.0/24 any 80)")
        print("Type 'done' when finished.")
        while True:
            rule = input("Rule: ")
            if rule.lower() == 'done':
                break
            self.firewall_rules.append(rule)
        self.save_state()
        print("Firewall rules configured and saved.")

    def configure_acls(self):
        print("Configuring Access Control Lists (ACLs):")
        print("Enter ACLs one by one. Format: resource permission role (e.g., database read admin)")
        print("Type 'done' when finished.")
        while True:
            acl = input("ACL: ")
            if acl.lower() == 'done':
                break
            self.acls.append(acl)
        self.save_state()
        print("ACLs configured and saved.")

    def setup_encryption(self):
        print("Setting up Encryption:")
        print("1. Data at Rest")
        print("2. Data in Transit")
        choice = input("Choose: ")
        if choice == "1":
            method = input("Encryption method for data at rest (e.g., AES-256): ")
            self.encryption["at_rest"] = method
        elif choice == "2":
            method = input("Encryption method for data in transit (e.g., TLS 1.3): ")
            self.encryption["in_transit"] = method
        else:
            print("Invalid choice.")
        self.save_state()
        print("Encryption setup and saved.")

    def enforce_rbac(self):
        print("Enforcing Role-Based Access Control (RBAC):")
        print("Define roles and assign permissions.")
        role = input("Role name: ")
        permissions = input("Permissions (comma-separated): ").split(',')
        self.rbac["roles"][role] = [p.strip() for p in permissions]
        print("Assign role to user:")
        user = input("User: ")
        if user not in self.rbac["users"]:
            self.rbac["users"][user] = []
        self.rbac["users"][user].append(role)
        # Enforce least privilege: check if permissions are minimal
        if len(permissions) > 5:  # arbitrary check
            print("Warning: Role has many permissions. Consider least privilege.")
        self.save_state()
        print("RBAC enforced and saved.")

    def validate_controls(self):
        complete = (self.firewall_rules and self.acls and
                    self.encryption["at_rest"] and self.encryption["in_transit"] and
                    self.rbac["roles"])
        if complete:
            print("All security controls are configured.")
        else:
            print("Controls are incomplete.")
        return complete
