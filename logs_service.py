# Service 5: Security Audit Logging Service
# Zeinab Harb
#
# Every service already writes to the shared `logs` table through common.write_log() (logins, failed logins,
# user creation/deletion, role changes, unauthorized access, asset/incident/threat changes). This service
# exposes those records through the API and lets administrators add manual records.
# Audit logs are append-only: there is deliberately no working update route.
import re

from flask import Blueprint, g, request

from common import (ADMIN, ANALYST, AUDITOR, ROLES, ApiError, get_json_body, require_roles, set_developer,
                    success, write_log)
from models import AuditLog, LogRepository, UserRepository
from validators import (check_choice, check_date, check_int, check_string, clean_str, raise_if_errors,
                        reject_unknown_fields, require_fields)

DEVELOPER = "Zeinab Harb"
SERVICE = "Security Audit Logging"
# The nine system services; related_service must name one of them.
SERVICES = [
    "Users and Identity Management", "Asset Management", "Incident Management",
    "Threat Intelligence", "Security Audit Logging", "Security Reports",
    "Vulnerability Management", "Notification and Alert Management", "Security Playbook and Response Automation",
]
ACTION_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,49}$")

logs_bp = Blueprint("logs", __name__)
set_developer(logs_bp, DEVELOPER)
logs = LogRepository()
users = UserRepository()


def _get_log_or_404(log_id):
    log = logs.get_by_id(log_id)
    if log is None:
        raise ApiError(f"Log record with id {log_id} not found", 404)
    return log


def _with_user(log):
    """Log record plus the username that performed the action (Users -> Logs relationship)."""
    data = log.to_dict()
    user = users.get_by_id(log.user_id) if log.user_id is not None else None
    data["username"] = user.username if user else None
    return data


# ---------------------------------------------------------------- 1. Create Log Record (Zeinab Harb)
@logs_bp.route("/logs", methods=["POST"])
@require_roles(ADMIN, service=SERVICE)
def create_log():
    data = get_json_body()
    required = ["user_id", "action_performed", "description", "severity_level", "related_service"]
    reject_unknown_fields(data, required)
    require_fields(data, required)

    errors = {}
    check_int(errors, data, "user_id")
    check_string(errors, data, "action_performed", 50)
    check_string(errors, data, "description", 1000)
    check_choice(errors, data, "severity_level", AuditLog.SEVERITIES)
    check_choice(errors, data, "related_service", SERVICES)
    action = None
    if "action_performed" not in errors:
        action = re.sub(r"[\s-]+", "_", data["action_performed"].strip()).upper()
        if not ACTION_RE.match(action):
            errors["action_performed"] = ("Action must be 3-50 characters: letters, digits and underscores, "
                                          "e.g. FIREWALL_RULE_CHANGED")
    raise_if_errors(errors)

    if users.get_by_id(data["user_id"]) is None:
        raise ApiError(f"User with id {data['user_id']} does not exist", 404)

    log = logs.insert({
        "user_id": data["user_id"],
        "action_performed": action,
        "description": clean_str(data["description"]),
        "severity_level": data["severity_level"],
        "related_service": data["related_service"],
    })
    return success("Log record created successfully", _with_user(log), 201)


# ---------------------------------------------------------------- 2. Retrieve All Logs (Zeinab Harb)
@logs_bp.route("/logs", methods=["GET"])
@require_roles(ADMIN, AUDITOR, service=SERVICE)
def get_all_logs():
    all_logs = [_with_user(l) for l in logs.get_all()]
    return success(f"{len(all_logs)} log record(s) found (newest first)",
                   {"count": len(all_logs), "logs": all_logs})


# ---------------------------------------------------------------- 4. Search Logs (Zeinab Harb)
@logs_bp.route("/logs/search", methods=["GET"])
@require_roles(ADMIN, AUDITOR, ANALYST, service=SERVICE)
def search_logs():
    allowed = ["user", "date", "action", "severity", "service"]
    unknown = sorted(set(request.args) - set(allowed))
    if unknown:
        raise ApiError("Unknown search parameters", 400,
                       {p: f"Allowed parameters: {', '.join(allowed)}" for p in unknown})
    if not request.args:
        raise ApiError(f"Provide at least one search parameter: {', '.join(allowed)}", 400)

    args = {k: v.strip() for k, v in request.args.items()}
    errors = {k: "Cannot be empty" for k, v in args.items() if not v}
    check_date(errors, args, "date")
    check_choice(errors, args, "severity", AuditLog.SEVERITIES)
    raise_if_errors(errors)

    # `user` accepts either a numeric user id or a username
    user = args.get("user")
    user_id = int(user) if user is not None and user.isdigit() else None
    username = user if user is not None and user_id is None else None

    results = [_with_user(l) for l in logs.filter(user_id=user_id, username=username, date=args.get("date"),
                                                  action=args.get("action"), severity=args.get("severity"),
                                                  service=args.get("service"))]
    return success(f"{len(results)} log record(s) match the search",
                   {"criteria": dict(request.args), "count": len(results), "logs": results})


# ---------------------------------------------------------------- 6. Retrieve Logs By User (Zeinab Harb)
@logs_bp.route("/logs/user/<int:user_id>", methods=["GET"])
@require_roles(ADMIN, AUDITOR, service=SERVICE)
def get_logs_by_user(user_id):
    user = users.get_by_id(user_id)
    if user is None:
        raise ApiError(f"User with id {user_id} not found", 404)
    user_logs = [l.to_dict() for l in logs.for_user(user_id)]
    message = (f"{len(user_logs)} log record(s) found for user '{user.username}'" if user_logs
               else f"User '{user.username}' has no recorded activity")
    return success(message, {"user": {"user_id": user.user_id, "username": user.username,
                                      "full_name": user.full_name, "role": user.role},
                             "count": len(user_logs), "logs": user_logs})


# ---------------------------------------------------------------- 3. Retrieve Specific Log (Zeinab Harb)
@logs_bp.route("/logs/<int:log_id>", methods=["GET"])
@require_roles(ADMIN, AUDITOR, ANALYST, service=SERVICE)
def get_log(log_id):
    return success("Log record found", _with_user(_get_log_or_404(log_id)))


# ---------------------------------------------------------------- 5. Delete Logs (Zeinab Harb)
@logs_bp.route("/logs/<int:log_id>", methods=["DELETE"])
@require_roles(ADMIN, service=SERVICE)
def delete_log(log_id):
    log = _get_log_or_404(log_id)
    logs.delete(log_id)
    # Deleting audit evidence is itself an auditable event
    write_log(g.current_user["user_id"], "LOG_DELETED",
              f"Log {log_id} ({log.action_performed}, {log.severity_level}, {log.timestamp}) deleted",
              "Warning", SERVICE)
    return success(f"Log record {log_id} deleted successfully",
                   {"deleted_log_id": log_id, "deleted_log": log.to_dict()})


# ---------------------------------------------------------------- Audit log protection (Zeinab Harb)
@logs_bp.route("/logs/<int:log_id>", methods=["PUT", "PATCH"])
@require_roles(*ROLES, service=SERVICE)
def reject_log_modification(log_id):
    write_log(g.current_user["user_id"], "LOG_MODIFICATION_BLOCKED",
              f"{g.current_user['role']} '{g.current_user['username']}' tried to modify log {log_id}",
              "Warning", SERVICE)
    raise ApiError("Audit logs cannot be modified after creation", 405)
