# Service 4: Threat Intelligence Service
# Zeinab Harb
from flask import Blueprint, g, request

from common import (ADMIN, ANALYST, AUDITOR, ApiError, get_json_body, require_roles, set_developer, success,
                    write_log)
from models import Threat, ThreatRepository
from validators import (check_choice, check_string, clean_str, normalize_threat_value, raise_if_errors,
                        reject_unknown_fields, require_fields)

DEVELOPER = "Zeinab Harb"
SERVICE = "Threat Intelligence"
UPDATABLE_FIELDS = ["description", "severity_level", "source"]

threats_bp = Blueprint("threats", __name__)
set_developer(threats_bp, DEVELOPER)
threats = ThreatRepository()


def _get_threat_or_404(threat_id):
    threat = threats.get_by_id(threat_id)
    if threat is None:
        raise ApiError(f"Threat indicator with id {threat_id} not found", 404)
    return threat


def _log_severity(threat_severity):
    """Critical/High threats are flagged as Warning in the audit log, the rest as Information."""
    return "Warning" if threat_severity in ("High", "Critical") else "Information"


# ---------------------------------------------------------------- 1. Add Threat Indicator (Zeinab Harb)
@threats_bp.route("/threats", methods=["POST"])
@require_roles(ADMIN, service=SERVICE)
def add_threat():
    data = get_json_body()
    required = ["threat_type", "threat_value", "description", "severity_level", "source"]
    reject_unknown_fields(data, required)
    require_fields(data, required)

    errors = {}
    check_choice(errors, data, "threat_type", Threat.TYPES)
    check_choice(errors, data, "severity_level", Threat.SEVERITIES)
    check_string(errors, data, "description", 1000)
    check_string(errors, data, "source", 100)
    value = None
    if "threat_type" not in errors:
        value, value_error = normalize_threat_value(data["threat_type"], data["threat_value"])
        if value_error:
            errors["threat_value"] = value_error
    raise_if_errors(errors)

    duplicate = threats.find_duplicate(data["threat_type"], value)
    if duplicate is not None:
        raise ApiError(f"Threat indicator {data['threat_type']} '{value}' already exists "
                       f"(threat id {duplicate.threat_id})", 409)

    threat = threats.insert({
        "threat_type": data["threat_type"],
        "threat_value": value,
        "description": clean_str(data["description"]),
        "severity_level": data["severity_level"],
        "source": clean_str(data["source"]),
    })
    write_log(g.current_user["user_id"], "THREAT_CREATED",
              f"Threat {threat.threat_id} added: {threat.threat_type} '{threat.threat_value}' "
              f"({threat.severity_level}, source: {threat.source})",
              _log_severity(threat.severity_level), SERVICE)
    return success("Threat indicator added successfully", threat.to_dict(), 201)


# ---------------------------------------------------------------- 2. Retrieve All Threat Indicators (Zeinab Harb)
@threats_bp.route("/threats", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, service=SERVICE)
def get_all_threats():
    all_threats = [t.to_dict() for t in threats.get_all()]
    return success(f"{len(all_threats)} threat indicator(s) found",
                   {"count": len(all_threats), "threats": all_threats})


# ---------------------------------------------------------------- 4. Search Threat Indicators (Zeinab Harb)
# Registered before /threats/<id> for readability; the <int:> converter keeps the two routes apart anyway.
@threats_bp.route("/threats/search", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, service=SERVICE)
def search_threats():
    # query parameter -> (column, exact match?)
    criteria = {
        "type": ("threat_type", True),
        "value": ("threat_value", False),
        "severity": ("severity_level", True),
        "source": ("source", False),
    }
    unknown = sorted(set(request.args) - set(criteria))
    if unknown:
        raise ApiError("Unknown search parameters", 400,
                       {p: f"Allowed parameters: {', '.join(criteria)}" for p in unknown})
    if not request.args:
        raise ApiError(f"Provide at least one search parameter: {', '.join(criteria)}", 400)

    errors = {}
    check_choice(errors, request.args, "type", Threat.TYPES)
    check_choice(errors, request.args, "severity", Threat.SEVERITIES)
    for param in ("value", "source"):
        if param in request.args and not request.args[param].strip():
            errors[param] = "Cannot be empty"
    raise_if_errors(errors)

    exact, partial = {}, {}
    for param, value in request.args.items():
        column, is_exact = criteria[param]
        (exact if is_exact else partial)[column] = value.strip()

    results = [t.to_dict() for t in threats.search(exact, partial)]
    return success(f"{len(results)} threat indicator(s) match the search",
                   {"criteria": dict(request.args), "count": len(results), "threats": results})


# ---------------------------------------------------------------- 3. Retrieve Specific Threat Indicator (Zeinab Harb)
@threats_bp.route("/threats/<int:threat_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, service=SERVICE)
def get_threat(threat_id):
    return success("Threat indicator found", _get_threat_or_404(threat_id).to_dict())


# ---------------------------------------------------------------- 5. Update Threat Information (Zeinab Harb)
@threats_bp.route("/threats/<int:threat_id>", methods=["PUT"])
@require_roles(ADMIN, service=SERVICE)
def update_threat(threat_id):
    data = get_json_body()
    locked = [f for f in ("threat_type", "threat_value", "threat_id", "date_added") if f in data]
    if locked:
        raise ApiError("These fields cannot be changed", 400,
                       {f: "Read-only. To change the indicator itself, delete it and add a new one" for f in locked})
    reject_unknown_fields(data, UPDATABLE_FIELDS)

    errors = {}
    check_string(errors, data, "description", 1000)
    check_string(errors, data, "source", 100)
    check_choice(errors, data, "severity_level", Threat.SEVERITIES)
    for field in UPDATABLE_FIELDS:
        if field in data and data[field] is None:
            errors[field] = "Cannot be null"
    raise_if_errors(errors)

    before = _get_threat_or_404(threat_id)
    after = threats.update(threat_id, {k: clean_str(v) for k, v in data.items()})
    changes = [f"{f}: '{getattr(before, f)}' -> '{getattr(after, f)}'"
               for f in data if getattr(before, f) != getattr(after, f)]
    write_log(g.current_user["user_id"], "THREAT_UPDATED",
              f"Threat {threat_id} ({after.threat_type} '{after.threat_value}') updated: "
              + ("; ".join(changes) if changes else "no values changed"),
              _log_severity(after.severity_level), SERVICE)
    return success("Threat information updated successfully", {"before": before.to_dict(), "after": after.to_dict()})


# ---------------------------------------------------------------- 6. Delete Threat Indicator (Zeinab Harb)
@threats_bp.route("/threats/<int:threat_id>", methods=["DELETE"])
@require_roles(ADMIN, service=SERVICE)
def delete_threat(threat_id):
    threat = _get_threat_or_404(threat_id)
    threats.delete(threat_id)
    write_log(g.current_user["user_id"], "THREAT_DELETED",
              f"Threat {threat_id} deleted: {threat.threat_type} '{threat.threat_value}' ({threat.severity_level})",
              "Warning", SERVICE)
    return success(f"Threat indicator {threat_id} deleted successfully",
                   {"deleted_threat_id": threat_id, "deleted_threat": threat.to_dict()})
