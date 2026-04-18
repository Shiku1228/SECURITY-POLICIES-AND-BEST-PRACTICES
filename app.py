from flask import Flask, render_template, request, jsonify
from security_policies import SecurityPolicyManager
from security_controls import SecurityControlsManager
from compliance_audit import ComplianceAuditor
from incident_response import IncidentResponseManager

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
    return render_template('index.html')

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

# --- Controls API ---
@app.route('/api/controls/state', methods=['GET'])
def get_controls():
    return jsonify({
        "firewall_rules": controls_manager.firewall_rules,
        "acls": controls_manager.acls,
        "encryption": controls_manager.encryption,
        "rbac": controls_manager.rbac
    })

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
    incident = incident_responder.simulate_breach()
    return jsonify({"success": True, "incident": incident})

@app.route('/api/incidents/history', methods=['GET'])
def get_incident_history():
    return jsonify(incident_responder.incident_log)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
