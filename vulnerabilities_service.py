# Service 7: Vulnerability Management Service
# Omar Obeid
from datetime import datetime

from flask import Blueprint, g, request

from common import (ADMIN, ANALYST, AUDITOR, ApiError, get_json_body, require_roles, set_developer, success,
                    write_log)
from models import AssetRepository, Vulnerability, VulnerabilityRepository
from notifications_service import send_notification
from validators import (check_choice, check_cve, check_cvss, check_int, check_string, clean_str, parse_datetime,
                        raise_if_errors, reject_unknown_fields, require_fields)

DEVELOPER = "Omar Obeid"
SERVICE = "Vulnerability Management"
CREATE_FIELDS = ["title", "description", "cve_identifier", "cvss_score", "severity_level", "affected_asset_id",
                 "discovery_source"]
UPDATABLE_FIELDS = ["description", "severity_level", "status", "cvss_score", "resolution_date"]

vulnerabilities_bp = Blueprint("vulnerabilities", __name__)
set_developer(vulnerabilities_bp, DEVELOPER)
vulnerabilities = VulnerabilityRepository()
assets = AssetRepository()


def _get_vulnerability_or_404(vulnerability_id):
    vulnerability = vulnerabilities.get_by_id(vulnerability_id)
    if vulnerability is None:
        raise ApiError(f"Vulnerability with id {vulnerability_id} not found", 404)
    return vulnerability


def _check_severity_matches_score(errors, score, severity):
    expected = Vulnerability.severity_for_score(score)
    if severity != expected:
        errors["severity_level"] = (f"Severity '{severity}' does not match CVSS score {score}; "
                                    f"expected '{expected}' (0-3.9 Low, 4-6.9 Medium, 7-8.9 High, 9-10 Critical)")


def _present(vulnerability):
    data = vulnerability.to_dict()
    asset = assets.get_by_id(vulnerability.affected_asset_id)
    data["affected_asset"] = ({"asset_id": asset.asset_id, "asset_name": asset.asset_name,
                               "ip_address": asset.ip_address, "criticality_level": asset.criticality_level}
                              if asset else None)
    return data


def _log_severity(vulnerability_severity):
    return "Warning" if vulnerability_severity in ("High", "Critical") else "Information"


# ---------------------------------------------------------------- 1. Create Vulnerability Record (Omar Obeid)
@vulnerabilities_bp.route("/vulnerabilities", methods=["POST"])
@require_roles(ADMIN, service=SERVICE)
def create_vulnerability():
    data = get_json_body()
    reject_unknown_fields(data, CREATE_FIELDS)
    require_fields(data, CREATE_FIELDS)

    errors = {}
    check_string(errors, data, "title", 150)
    check_string(errors, data, "description", 2000)
    check_string(errors, data, "discovery_source", 100)
    check_cve(errors, data)
    check_cvss(errors, data)
    check_choice(errors, data, "severity_level", Vulnerability.SEVERITIES)
    check_int(errors, data, "affected_asset_id")
    if "cvss_score" not in errors and "severity_level" not in errors:
        _check_severity_matches_score(errors, data["cvss_score"], data["severity_level"])
    raise_if_errors(errors)

    asset = assets.get_by_id(data["affected_asset_id"])
    if asset is None:
        raise ApiError(f"Affected asset with id {data['affected_asset_id']} does not exist", 404)
    cve = data["cve_identifier"].strip().upper()
    duplicate = vulnerabilities.find_duplicate(cve, asset.asset_id)
    if duplicate is not None:
        raise ApiError(f"{cve} is already recorded on asset '{asset.asset_name}' "
                       f"(vulnerability id {duplicate.vulnerability_id})", 409)

    vulnerability = vulnerabilities.insert({
        "title": clean_str(data["title"]),
        "description": clean_str(data["description"]),
        "cve_identifier": cve,
        "cvss_score": float(data["cvss_score"]),
        "severity_level": data["severity_level"],
        "affected_asset_id": asset.asset_id,
        "discovery_source": clean_str(data["discovery_source"]),
    })
    write_log(g.current_user["user_id"], "VULNERABILITY_CREATED",
              f"Vulnerability {vulnerability.vulnerability_id} {cve} (CVSS {vulnerability.cvss_score}, "
              f"{vulnerability.severity_level}) recorded on asset {asset.asset_id} '{asset.asset_name}'",
              _log_severity(vulnerability.severity_level), SERVICE)
    if vulnerability.severity_level in ("High", "Critical"):
        send_notification(asset.owner_id, f"{vulnerability.severity_level} vulnerability on {asset.asset_name}",
                          f"{cve} '{vulnerability.title}' (CVSS {vulnerability.cvss_score}) was found on your "
                          f"asset '{asset.asset_name}'", "Vulnerability Alert", vulnerability.severity_level)
    return success("Vulnerability record created successfully", _present(vulnerability), 201)


# ---------------------------------------------------------------- 2. Retrieve All Vulnerabilities (Omar Obeid)
@vulnerabilities_bp.route("/vulnerabilities", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, service=SERVICE)
def get_all_vulnerabilities():
    all_vulnerabilities = [_present(v) for v in vulnerabilities.get_all()]
    return success(f"{len(all_vulnerabilities)} vulnerability record(s) found",
                   {"count": len(all_vulnerabilities), "vulnerabilities": all_vulnerabilities})


# ---------------------------------------------------------------- 5. Search Vulnerabilities (Omar Obeid)
@vulnerabilities_bp.route("/vulnerabilities/search", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, service=SERVICE)
def search_vulnerabilities():
    allowed = ["cve", "severity", "asset", "status"]
    unknown = sorted(set(request.args) - set(allowed))
    if unknown:
        raise ApiError("Unknown search parameters", 400,
                       {p: f"Allowed parameters: {', '.join(allowed)}" for p in unknown})
    if not request.args:
        raise ApiError(f"Provide at least one search parameter: {', '.join(allowed)}", 400)

    errors = {}
    check_choice(errors, request.args, "severity", Vulnerability.SEVERITIES)
    check_choice(errors, request.args, "status", Vulnerability.STATUS_FLOW)
    if "cve" in request.args and not request.args["cve"].strip():
        errors["cve"] = "Cannot be empty"
    asset = request.args.get("asset", "").strip()
    if "asset" in request.args and not (asset.isdigit() and int(asset) > 0):
        errors["asset"] = "Must be a positive asset id"
    raise_if_errors(errors)

    exact, partial = {}, {}
    if "cve" in request.args:
        partial["cve_identifier"] = request.args["cve"].strip()
    if "severity" in request.args:
        exact["severity_level"] = request.args["severity"]
    if "status" in request.args:
        exact["status"] = request.args["status"]
    if "asset" in request.args:
        exact["affected_asset_id"] = int(asset)

    results = [_present(v) for v in vulnerabilities.search(exact, partial)]
    return success(f"{len(results)} vulnerability record(s) match the search",
                   {"criteria": dict(request.args), "count": len(results), "vulnerabilities": results})


# ---------------------------------------------------------------- 3. Retrieve Specific Vulnerability (Omar Obeid)
@vulnerabilities_bp.route("/vulnerabilities/<int:vulnerability_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, service=SERVICE)
def get_vulnerability(vulnerability_id):
    return success("Vulnerability found", _present(_get_vulnerability_or_404(vulnerability_id)))


# ---------------------------------------------------------------- 4. Update Vulnerability Status (Omar Obeid)
@vulnerabilities_bp.route("/vulnerabilities/<int:vulnerability_id>", methods=["PUT"])
@require_roles(ADMIN, ANALYST, service=SERVICE)
def update_vulnerability(vulnerability_id):
    data = get_json_body()
    locked = [f for f in ("title", "cve_identifier", "affected_asset_id", "discovery_source",
                          "vulnerability_id", "creation_date") if f in data]
    if locked:
        raise ApiError("These fields cannot be changed", 400,
                       {f: "Read-only. Delete the record and create a new one instead" for f in locked})
    reject_unknown_fields(data, UPDATABLE_FIELDS)

    errors = {}
    for f in UPDATABLE_FIELDS:
        if f in data and data[f] is None:
            errors[f] = "Cannot be null"
    check_string(errors, data, "description", 2000)
    check_choice(errors, data, "severity_level", Vulnerability.SEVERITIES)
    check_choice(errors, data, "status", Vulnerability.STATUS_FLOW)
    check_cvss(errors, data)
    resolution_date = parse_datetime(errors, data, "resolution_date")
    raise_if_errors(errors)

    before = _get_vulnerability_or_404(vulnerability_id)
    values = {k: clean_str(v) for k, v in data.items() if k != "resolution_date"}
    new_status = data.get("status", before.status)

    if "status" in data and new_status != before.status and not before.can_transition_to(new_status):
        expected = before.next_status()
        raise ApiError(f"Invalid status transition '{before.status}' -> '{new_status}'. "
                       + (f"Next allowed status is '{expected}'" if expected else "Vulnerability is already Closed"),
                       400, {"allowed_flow": " -> ".join(Vulnerability.STATUS_FLOW)})

    # severity must still agree with the score after the update
    score = data.get("cvss_score", before.cvss_score)
    severity = data.get("severity_level", before.severity_level)
    if "cvss_score" in data or "severity_level" in data:
        _check_severity_matches_score(errors, score, severity)

    if resolution_date is not None:
        if new_status not in ("Resolved", "Closed"):
            errors["resolution_date"] = "Only allowed when the vulnerability is Resolved or Closed"
        elif resolution_date < before.creation_date:
            errors["resolution_date"] = f"Cannot be before the creation date {before.creation_date}"
        else:
            values["resolution_date"] = resolution_date
    elif new_status == "Resolved" and before.status != "Resolved":
        values["resolution_date"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    raise_if_errors(errors)

    after = vulnerabilities.update(vulnerability_id, values)
    changes = [f"{f}: '{getattr(before, f)}' -> '{getattr(after, f)}'"
               for f in UPDATABLE_FIELDS if getattr(before, f) != getattr(after, f)]
    action = "VULNERABILITY_STATUS_CHANGED" if before.status != after.status else "VULNERABILITY_UPDATED"
    write_log(g.current_user["user_id"], action,
              f"Vulnerability {vulnerability_id} {after.cve_identifier} updated: "
              + ("; ".join(changes) if changes else "no values changed"),
              _log_severity(after.severity_level), SERVICE)
    message = (f"Vulnerability status updated from '{before.status}' to '{after.status}'"
               if before.status != after.status else "Vulnerability updated successfully")
    return success(message, {"before": _present(before), "after": _present(after)})


# ---------------------------------------------------------------- 6. Delete Vulnerability (Omar Obeid)
@vulnerabilities_bp.route("/vulnerabilities/<int:vulnerability_id>", methods=["DELETE"])
@require_roles(ADMIN, service=SERVICE)
def delete_vulnerability(vulnerability_id):
    vulnerability = _get_vulnerability_or_404(vulnerability_id)
    vulnerabilities.delete(vulnerability_id)
    write_log(g.current_user["user_id"], "VULNERABILITY_DELETED",
              f"Vulnerability {vulnerability_id} {vulnerability.cve_identifier} '{vulnerability.title}' "
              f"(status {vulnerability.status}) deleted", "Warning", SERVICE)
    return success(f"Vulnerability {vulnerability_id} deleted successfully",
                   {"deleted_vulnerability_id": vulnerability_id, "deleted_vulnerability": vulnerability.to_dict()})
