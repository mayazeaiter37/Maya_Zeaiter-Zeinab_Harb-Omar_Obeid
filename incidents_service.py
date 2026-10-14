# Service 3: Incident Management Service
# Maya Zeaiter
from datetime import datetime

from flask import Blueprint, g

from common import (ADMIN, ANALYST, AUDITOR, REGULAR, ApiError, deny, get_json_body, require_roles, success,
                    write_log)
from database import connect_to_db
from models import AssetRepository, Incident, IncidentRepository, UserRepository
from validators import (check_choice, check_int, check_string, clean_str, raise_if_errors, reject_unknown_fields,
                        require_fields)

SERVICE = "Incident Management"
SEVERITIES = ["Low", "Medium", "High", "Critical"]
CATEGORIES = ["Malware Infection", "Unauthorized Access", "Phishing Attack", "Data Leakage",
              "Account Compromise", "Denial of Service", "Other"]

incidents_bp = Blueprint("incidents", __name__)
incidents = IncidentRepository()
users = UserRepository()
assets = AssetRepository()


def _get_incident_or_404(incident_id):
    incident = incidents.get_by_id(incident_id)
    if incident is None:
        raise ApiError(f"Incident with id {incident_id} not found", 404)
    return incident


def _check_incident_access(incident):
    """Analysts only see incidents assigned to them; regular users only those they reported."""
    caller = g.current_user
    if caller["role"] == ANALYST and incident.assigned_analyst_id != caller["user_id"]:
        deny("Security Analysts can only access incidents assigned to them", SERVICE)
    if caller["role"] == REGULAR and incident.reporter_id != caller["user_id"]:
        deny("Users can only access incidents they reported", SERVICE)


def _username(user_id):
    user = users.get_by_id(user_id) if user_id else None
    return user.username if user else None


def _present(incident):
    data = incident.to_dict()
    data["reporter_username"] = _username(incident.reporter_id)
    data["assigned_analyst_username"] = _username(incident.assigned_analyst_id)
    return data


def _notify(user_id, title, message, severity):
    """Notification for the Notification and Alert Management Service's table."""
    conn = connect_to_db()
    try:
        conn.execute("INSERT INTO notifications (user_id, title, message, notification_type, severity_level) "
                     "VALUES (?, ?, ?, 'Incident Assignment', ?)", (user_id, title, message, severity))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------- 1. Create Incident (Maya Zeaiter)
@incidents_bp.route("/incidents", methods=["POST"])
@require_roles(ADMIN, REGULAR, service=SERVICE)
def create_incident():
    caller = g.current_user
    data = get_json_body()
    required = ["title", "description", "category", "severity", "asset_id"]
    allowed = required + (["reporter_id"] if caller["role"] == ADMIN else [])
    reject_unknown_fields(data, allowed)
    require_fields(data, required)

    errors = {}
    check_string(errors, data, "title", 150)
    check_string(errors, data, "description", 2000)
    check_choice(errors, data, "category", CATEGORIES)
    check_choice(errors, data, "severity", SEVERITIES)
    check_int(errors, data, "asset_id")
    check_int(errors, data, "reporter_id")
    raise_if_errors(errors)

    if assets.get_by_id(data["asset_id"]) is None:
        raise ApiError(f"Affected asset with id {data['asset_id']} does not exist", 404)
    reporter_id = data.get("reporter_id", caller["user_id"])
    if users.get_by_id(reporter_id) is None:
        raise ApiError(f"Reporter with user id {reporter_id} does not exist", 404)

    incident = incidents.insert({
        "title": clean_str(data["title"]),
        "description": clean_str(data["description"]),
        "category": data["category"],
        "severity": data["severity"],
        "reporter_id": reporter_id,
        "asset_id": data["asset_id"],
    })
    write_log(caller["user_id"], "INCIDENT_CREATED",
              f"Incident {incident.incident_id} '{incident.title}' ({incident.severity}) reported",
              "Critical" if incident.severity == "Critical" else "Information", SERVICE)
    return success("Incident created successfully", _present(incident), 201)


# ---------------------------------------------------------------- 2. Retrieve All Incidents (Maya Zeaiter)
@incidents_bp.route("/incidents", methods=["GET"])
@require_roles(ADMIN, AUDITOR, service=SERVICE)
def get_all_incidents():
    all_incidents = [_present(i) for i in incidents.get_all()]
    return success(f"{len(all_incidents)} incident(s) found",
                   {"count": len(all_incidents), "incidents": all_incidents})


# ---------------------------------------------------------------- 3. Retrieve Specific Incident (Maya Zeaiter)
@incidents_bp.route("/incidents/<int:incident_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, REGULAR, service=SERVICE)
def get_incident(incident_id):
    incident = _get_incident_or_404(incident_id)
    _check_incident_access(incident)
    return success("Incident found", _present(incident))


# ---------------------------------------------------------------- 4. Assign Incident to Analyst (Maya Zeaiter)
@incidents_bp.route("/incidents/<int:incident_id>/assign", methods=["PUT"])
@require_roles(ADMIN, service=SERVICE)
def assign_incident(incident_id):
    data = get_json_body()
    reject_unknown_fields(data, ["analyst_id"])
    require_fields(data, ["analyst_id"])
    errors = {}
    check_int(errors, data, "analyst_id")
    raise_if_errors(errors)

    incident = _get_incident_or_404(incident_id)
    if incident.status == "Closed":
        raise ApiError("Closed incidents cannot be reassigned", 409)
    analyst = users.get_by_id(data["analyst_id"])
    if analyst is None:
        raise ApiError(f"User with id {data['analyst_id']} not found", 404)
    if analyst.role != ANALYST:
        raise ApiError(f"User '{analyst.username}' is a '{analyst.role}', not a Security Analyst", 400)
    if analyst.account_status != "Active":
        raise ApiError(f"Analyst '{analyst.username}' account is {analyst.account_status}", 400)

    updated = incidents.update(incident_id, {"assigned_analyst_id": analyst.user_id})
    write_log(g.current_user["user_id"], "INCIDENT_ASSIGNED",
              f"Incident {incident_id} assigned to analyst '{analyst.username}' (id {analyst.user_id})",
              "Information", SERVICE)
    _notify(analyst.user_id, "New incident assigned",
            f"Incident #{incident_id} '{incident.title}' has been assigned to you", incident.severity)
    return success(f"Incident assigned to {analyst.full_name}", _present(updated))


# ---------------------------------------------------------------- 5. Update Incident Status (Maya Zeaiter)
@incidents_bp.route("/incidents/<int:incident_id>/status", methods=["PUT"])
@require_roles(ADMIN, ANALYST, service=SERVICE)
def update_incident_status(incident_id):
    data = get_json_body()
    reject_unknown_fields(data, ["status"])
    require_fields(data, ["status"])
    errors = {}
    check_choice(errors, data, "status", Incident.STATUS_FLOW)
    raise_if_errors(errors)

    incident = _get_incident_or_404(incident_id)
    _check_incident_access(incident)
    new_status = data["status"]

    if not incident.can_transition_to(new_status):
        expected = incident.next_status()
        raise ApiError(f"Invalid status transition '{incident.status}' -> '{new_status}'. "
                       + (f"Next allowed status is '{expected}'" if expected else "Incident is already Closed"),
                       400, {"allowed_flow": " -> ".join(Incident.STATUS_FLOW)})
    if new_status == "Under Investigation" and incident.assigned_analyst_id is None:
        raise ApiError("Assign the incident to a Security Analyst before starting the investigation", 400)
    if new_status == "Closed" and g.current_user["role"] != ADMIN:
        deny("Only a Security Administrator can close incidents", SERVICE)

    values = {"status": new_status}
    if new_status == "Resolved":
        values["resolution_date"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    updated = incidents.update(incident_id, values)
    write_log(g.current_user["user_id"], "INCIDENT_STATUS_CHANGED",
              f"Incident {incident_id} status '{incident.status}' -> '{new_status}'", "Information", SERVICE)
    return success(f"Incident status updated from '{incident.status}' to '{new_status}'", _present(updated))


# ---------------------------------------------------------------- 6. Add Investigation Notes (Maya Zeaiter)
@incidents_bp.route("/incidents/<int:incident_id>/notes", methods=["POST"])
@require_roles(ADMIN, ANALYST, service=SERVICE)
def add_investigation_note(incident_id):
    data = get_json_body()
    reject_unknown_fields(data, ["note_content"])
    require_fields(data, ["note_content"])
    errors = {}
    check_string(errors, data, "note_content", 5000)
    raise_if_errors(errors)

    incident = _get_incident_or_404(incident_id)
    _check_incident_access(incident)
    if incident.status == "Closed":
        raise ApiError("Notes cannot be added to a Closed incident", 409)

    note = incidents.notes.insert({
        "incident_id": incident_id,
        "analyst_id": g.current_user["user_id"],
        "note_content": clean_str(data["note_content"]),
    })
    write_log(g.current_user["user_id"], "INCIDENT_NOTE_ADDED",
              f"Note {note.note_id} added to incident {incident_id}", "Information", SERVICE)
    return success("Investigation note added", {"note": note.to_dict(),
                                                 "incident": _present(incidents.get_by_id(incident_id))}, 201)
