# Service 9: Security Playbook and Response Automation Service
# Omar Obeid
from datetime import datetime

from flask import Blueprint, g

from common import (ADMIN, ANALYST, AUDITOR, ApiError, deny, get_json_body, require_roles, set_developer, success,
                    write_log)
from incidents_service import CATEGORIES
from models import Playbook, PlaybookRepository, ResponseAction, UserRepository
from notifications_service import send_notification
from validators import (check_choice, check_int, check_string, clean_str, parse_datetime, raise_if_errors,
                        reject_unknown_fields, require_fields)

DEVELOPER = "Omar Obeid"
SERVICE = "Security Playbook and Response Automation"
RESPONDER_ROLES = (ADMIN, ANALYST)  # roles that can be assigned a response action

playbooks_bp = Blueprint("playbooks", __name__)
set_developer(playbooks_bp, DEVELOPER)
playbooks = PlaybookRepository()
actions = playbooks.actions
users = UserRepository()


def _get_playbook_or_404(playbook_id):
    playbook = playbooks.get_by_id(playbook_id)
    if playbook is None:
        raise ApiError(f"Playbook with id {playbook_id} not found", 404)
    return playbook


def _get_responder(user_id):
    """The user must exist, be Active and be an Administrator or Analyst."""
    user = users.get_by_id(user_id)
    if user is None:
        raise ApiError(f"User with id {user_id} not found", 404)
    if user.role not in RESPONDER_ROLES:
        raise ApiError(f"User '{user.username}' is a '{user.role}'; response actions can only be assigned to "
                       f"a Security Administrator or Security Analyst", 400)
    if user.account_status != "Active":
        raise ApiError(f"User '{user.username}' account is {user.account_status}", 400)
    return user


def _notify_assignment(user, action, playbook_name):
    send_notification(user.user_id, "Response action assigned",
                      f"Step {action.step_number} of playbook '{playbook_name}' is assigned to you: "
                      f"{action.action_description}", "System Notification", "Medium")


# ---------------------------------------------------------------- 1. Create Playbook (Omar Obeid)
@playbooks_bp.route("/playbooks", methods=["POST"])
@require_roles(ADMIN, service=SERVICE)
def create_playbook():
    data = get_json_body()
    required = ["playbook_name", "description", "incident_category", "severity_level"]
    reject_unknown_fields(data, required)
    require_fields(data, required)

    errors = {}
    check_string(errors, data, "playbook_name", 100)
    check_string(errors, data, "description", 2000)
    check_choice(errors, data, "incident_category", CATEGORIES)
    check_choice(errors, data, "severity_level", Playbook.SEVERITIES)
    raise_if_errors(errors)

    name = clean_str(data["playbook_name"])
    existing = playbooks.find_by_name(name)
    if existing is not None:
        raise ApiError(f"A playbook named '{existing.playbook_name}' already exists "
                       f"(playbook id {existing.playbook_id})", 409)

    playbook = playbooks.insert({
        "playbook_name": name,
        "description": clean_str(data["description"]),
        "incident_category": data["incident_category"],
        "severity_level": data["severity_level"],
        "created_by": g.current_user["user_id"],
    })
    write_log(g.current_user["user_id"], "PLAYBOOK_CREATED",
              f"Playbook {playbook.playbook_id} '{playbook.playbook_name}' created for "
              f"{playbook.incident_category} ({playbook.severity_level})", "Information", SERVICE)
    return success("Playbook created successfully", playbook.to_dict(), 201)


# ---------------------------------------------------------------- 2. Retrieve All Playbooks (Omar Obeid)
@playbooks_bp.route("/playbooks", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, service=SERVICE)
def get_all_playbooks():
    summaries = []
    for playbook in playbooks.get_all():
        data = playbook.to_dict()
        data.pop("actions")  # the list stays short; GET /playbooks/{id} shows the steps
        summaries.append(data)
    return success(f"{len(summaries)} playbook(s) found", {"count": len(summaries), "playbooks": summaries})


# ---------------------------------------------------------------- 3. Retrieve Specific Playbook (Omar Obeid)
@playbooks_bp.route("/playbooks/<int:playbook_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, service=SERVICE)
def get_playbook(playbook_id):
    return success("Playbook found", _get_playbook_or_404(playbook_id).to_dict())


# ---------------------------------------------------------------- 4. Add Response Action (Omar Obeid)
@playbooks_bp.route("/playbooks/<int:playbook_id>/actions", methods=["POST"])
@require_roles(ADMIN, ANALYST, service=SERVICE)
def add_response_action(playbook_id):
    data = get_json_body()
    reject_unknown_fields(data, ["action_description", "step_number", "assigned_user_id"])
    require_fields(data, ["action_description", "step_number"])

    errors = {}
    check_string(errors, data, "action_description", 1000)
    check_int(errors, data, "step_number")
    check_int(errors, data, "assigned_user_id")
    raise_if_errors(errors)

    playbook = _get_playbook_or_404(playbook_id)
    if actions.step_taken(playbook_id, data["step_number"]):
        raise ApiError(f"Playbook '{playbook.playbook_name}' already has a step {data['step_number']}", 409,
                       {"existing_steps": ", ".join(str(a.step_number) for a in playbook.actions)})
    assignee = _get_responder(data["assigned_user_id"]) if "assigned_user_id" in data else None

    action = actions.insert({
        "playbook_id": playbook_id,
        "action_description": clean_str(data["action_description"]),
        "step_number": data["step_number"],
        "assigned_user_id": assignee.user_id if assignee else None,
    })
    write_log(g.current_user["user_id"], "RESPONSE_ACTION_ADDED",
              f"Step {action.step_number} (action {action.action_id}) added to playbook {playbook_id}"
              + (f", assigned to '{assignee.username}'" if assignee else ""), "Information", SERVICE)
    if assignee:
        _notify_assignment(assignee, action, playbook.playbook_name)
    return success(f"Step {action.step_number} added to playbook '{playbook.playbook_name}'",
                   {"action": action.to_dict(), "playbook": _get_playbook_or_404(playbook_id).to_dict()}, 201)


# ---------------------------------------------------------------- 5. Update Response Action Status (Omar Obeid)
@playbooks_bp.route("/actions/<int:action_id>/status", methods=["PUT"])
@require_roles(ADMIN, ANALYST, service=SERVICE)
def update_action_status(action_id):
    data = get_json_body()
    reject_unknown_fields(data, ["status", "assigned_user_id", "completion_date"])
    require_fields(data, ["status"])

    errors = {}
    check_choice(errors, data, "status", ResponseAction.STATUS_FLOW)
    check_int(errors, data, "assigned_user_id")
    completion_date = parse_datetime(errors, data, "completion_date")
    raise_if_errors(errors)

    before = actions.get_by_id(action_id)
    if before is None:
        raise ApiError(f"Response action with id {action_id} not found", 404)
    caller = g.current_user
    if caller["role"] == ANALYST and before.assigned_user_id not in (None, caller["user_id"]):
        deny("Security Analysts can only update response actions assigned to them", SERVICE)

    new_status = data["status"]
    if not before.can_transition_to(new_status):
        expected = before.next_status()
        raise ApiError(f"Invalid status transition '{before.status}' -> '{new_status}'. "
                       + (f"Next allowed status is '{expected}'" if expected else "Action is already Completed"),
                       400, {"allowed_flow": " -> ".join(ResponseAction.STATUS_FLOW)})
    if new_status == "In Progress":
        waiting = actions.unfinished_before(before.playbook_id, before.step_number)
        if waiting:
            raise ApiError(f"Complete the earlier steps first: "
                           + ", ".join(f"step {a.step_number} ({a.status})" for a in waiting), 409)
    if completion_date is not None and new_status != "Completed":
        raise ApiError("Validation failed", 400, {"completion_date": "Only allowed when status is Completed"})

    values = {"status": new_status}
    assignee = None
    if "assigned_user_id" in data:
        if caller["role"] == ANALYST and data["assigned_user_id"] != caller["user_id"]:
            deny("Security Analysts can only assign response actions to themselves", SERVICE)
        assignee = _get_responder(data["assigned_user_id"])
        values["assigned_user_id"] = assignee.user_id
    elif before.assigned_user_id is None:
        values["assigned_user_id"] = caller["user_id"]  # whoever starts an unassigned step owns it
    if new_status == "Completed":
        values["completion_date"] = completion_date or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    after = actions.update(action_id, values)
    write_log(caller["user_id"], "RESPONSE_ACTION_STATUS_CHANGED",
              f"Action {action_id} (playbook {after.playbook_id}, step {after.step_number}) "
              f"'{before.status}' -> '{after.status}', assigned user {after.assigned_user_id}", "Information", SERVICE)
    if assignee and assignee.user_id != before.assigned_user_id and assignee.user_id != caller["user_id"]:
        _notify_assignment(assignee, after, playbooks.get_by_id(after.playbook_id, with_actions=False).playbook_name)
    return success(f"Action status updated from '{before.status}' to '{after.status}'",
                   {"before": before.to_dict(), "after": after.to_dict(),
                    "playbook_progress": _get_playbook_or_404(after.playbook_id).progress()})


# ---------------------------------------------------------------- 6. Delete Playbook (Omar Obeid)
@playbooks_bp.route("/playbooks/<int:playbook_id>", methods=["DELETE"])
@require_roles(ADMIN, service=SERVICE)
def delete_playbook(playbook_id):
    playbook = _get_playbook_or_404(playbook_id)
    playbooks.delete(playbook_id)  # response_actions are removed by ON DELETE CASCADE
    write_log(g.current_user["user_id"], "PLAYBOOK_DELETED",
              f"Playbook {playbook_id} '{playbook.playbook_name}' deleted with its "
              f"{len(playbook.actions)} response action(s)", "Warning", SERVICE)
    return success(f"Playbook {playbook_id} deleted with {len(playbook.actions)} response action(s)",
                   {"deleted_playbook_id": playbook_id, "deleted_actions": len(playbook.actions),
                    "deleted_playbook": playbook.to_dict()})
