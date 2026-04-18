from flask import Flask, render_template, request, jsonify, redirect, url_for
from security_policies import SecurityPolicyManager, PasswordPolicy, NetworkAccessPolicy, DataProtectionPolicy
from security_controls import SecurityControlsManager
from compliance_audit import ComplianceAuditor
from incident_response import IncidentResponseManager
import datetime

app = Flask(__name__)

# Initialize Managers
policy_manager = SecurityPolicyManager()
controls_manager = SecurityControlsManager()
controls_manager.load_state()

auditor = ComplianceAuditor()
auditor.load_state()

incident_responder = IncidentResponseManager()
incident_responder.load_state()

@app.route('/')
def index():
    return redirect(url_for('admin'))

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/demo')
def demo():
    return render_template('demo.html')

# --- Policy API ---
@app.route('/api/policies/state', methods=['GET'])
def get_policies():
    policies_serializable = {}
    for k, v in policy_manager.policies.items():
        if v:
            policies_serializable[k] = {"content": v.details}
        else:
            policies_serializable[k] = {"content": None}

    return jsonify({
        "objectives": policy_manager.objectives,
        "scope": policy_manager.scope,
        "policies": policies_serializable
    })

@app.route('/api/policies/update', methods=['POST'])
def update_policy():
    data = request.json
    ptype = data.get('type')
    details = data.get('details')
    
    if ptype == "password":
        pol = PasswordPolicy()
        pol.details = details
        policy_manager.policies["password"] = pol
    elif ptype == "network_access":
        pol = NetworkAccessPolicy()
        pol.details = details
        policy_manager.policies["network_access"] = pol
    elif ptype == "data_protection":
        pol = DataProtectionPolicy()
        pol.details = details
        policy_manager.policies["data_protection"] = pol
        
    return jsonify({"success": True})

# --- Controls API ---
@app.route('/api/controls/state', methods=['GET'])
def get_controls():
    return jsonify({
        "firewall_rules": controls_manager.firewall_rules,
        "acls": controls_manager.acls,
        "encryption": controls_manager.encryption,
        "rbac": controls_manager.rbac
    })

@app.route('/api/controls/update', methods=['POST'])
def update_controls():
    data = request.json
    ctype = data.get('type')
    val = data.get('value')
    
    if ctype == 'firewall':
        if val not in controls_manager.firewall_rules:
            controls_manager.firewall_rules.append(val)
        else:
            controls_manager.firewall_rules.remove(val)
    elif ctype == 'acl':
        if val not in controls_manager.acls:
            controls_manager.acls.append(val)
        else:
            controls_manager.acls.remove(val)
    elif ctype == 'encryption_rest':
        controls_manager.encryption['at_rest'] = val
    elif ctype == 'encryption_transit':
        controls_manager.encryption['in_transit'] = val
        
    controls_manager.save_state()
    return jsonify({"success": True})

# --- Audits API ---
@app.route('/api/audits/conduct', methods=['POST'])
def conduct_audit():
    result = auditor.conduct_audit()
    return jsonify({"success": True, "result": result})

@app.route('/api/audits/history', methods=['GET'])
def get_audit_history():
    return jsonify(auditor.audit_history)

# --- Incident Response API ---
@app.route('/api/incidents/simulate', methods=['POST'])
def simulate_incident():
    # Admin manually triggering a generic breach
    incident = incident_responder.simulate_breach()
    return jsonify({"success": True, "incident": incident})

@app.route('/api/incidents/history', methods=['GET'])
def get_incident_history():
    return jsonify(incident_responder.incident_log)

@app.route('/api/incidents/resolve', methods=['POST'])
def resolve_incident():
    data = request.json
    inc_id = data.get('id')
    for inc in incident_responder.incident_log:
        if inc['id'] == inc_id:
            inc['status'] = 'Resolved'
            incident_responder.save_state()
            return jsonify({"success": True})
    return jsonify({"success": False, "error": "Not found"}), 404

# --- Demo APIs ---
@app.route('/api/demo/trigger', methods=['POST'])
def demo_trigger():
    data = request.json
    action = data.get('action')
    
    # Evaluate action against controls
    if action == "access_financials":
        # Check ACLs
        if "financials read employee" in controls_manager.acls:
            return jsonify({"success": True, "message": "Access Granted to Financial Records."})
        else:
            incident_responder.log_incident({
                "type": "Unauthorized Access Attempt",
                "description": "Employee tried to access restricted financial records."
            })
            return jsonify({"success": False, "message": "Access Denied by ACL. Incident logged."})
            
    elif action == "launch_ddos":
        if "drop any any 80" in controls_manager.firewall_rules:
            return jsonify({"success": False, "message": "DDoS Blocked by Firewall."})
        else:
            incident_responder.log_incident({
                "type": "DDoS Attack",
                "description": "Volumetric attack overwhelmed the web server."
            })
            return jsonify({"success": True, "message": "DDoS Successful. Server down."})
            
    elif action == "sql_injection":
        incident_responder.log_incident({
            "type": "SQL Injection",
            "description": "Attacker extracted database records via SQLi vulnerability."
        })
        if controls_manager.encryption.get('at_rest') == "AES-256":
            return jsonify({"success": False, "message": "Extracted Data is AES-256 Encrypted (Unreadable)."})
        else:
            return jsonify({"success": True, "message": "Extracted PLAINTEXT credentials!"})
        
    return jsonify({"success": False, "message": "Unknown action"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
