# Service 2: Asset Management Service
# Maya Zeaiter
from flask import Blueprint, g, request

from common import ADMIN, ANALYST, AUDITOR, ApiError, get_json_body, require_roles, success, write_log
from models import AssetRepository, IncidentRepository, UserRepository
from validators import (check_choice, check_int, check_ip, check_string, clean_str, raise_if_errors,
                        reject_unknown_fields, require_fields)

SERVICE = "Asset Management"
ASSET_TYPES = ["Server", "Workstation", "Database", "Application", "Network Device", "Cloud Resource"]
CRITICALITY_LEVELS = ["Low", "Medium", "High", "Critical"]
ASSET_STATUSES = ["Active", "Inactive", "Under Maintenance"]

assets_bp = Blueprint("assets", __name__)
assets = AssetRepository()
users = UserRepository()
incidents = IncidentRepository()


def _validate_asset(data):
    errors = {}
    for f in ("asset_name", "department", "operating_system", "location"):
        check_string(errors, data, f, 100)
    check_choice(errors, data, "asset_type", ASSET_TYPES)
    check_choice(errors, data, "criticality_level", CRITICALITY_LEVELS)
    check_choice(errors, data, "status", ASSET_STATUSES)
    check_int(errors, data, "owner_id")
    check_ip(errors, data)
    raise_if_errors(errors)
    if "owner_id" in data and users.get_by_id(data["owner_id"]) is None:
        raise ApiError(f"Owner with user id {data['owner_id']} does not exist", 404)


def _with_relations(asset):
    """Asset plus its owner and related incidents (relationships required by the spec)."""
    data = asset.to_dict()
    owner = users.get_by_id(asset.owner_id)
    data["owner"] = {"user_id": owner.user_id, "full_name": owner.full_name,
                     "username": owner.username} if owner else None
    related = incidents.search(exact={"asset_id": asset.asset_id})
    data["related_incidents"] = [{"incident_id": i.incident_id, "title": i.title, "severity": i.severity,
                                  "status": i.status} for i in related]
    return data


# ---------------------------------------------------------------- 1. Add New Asset (Maya Zeaiter)
@assets_bp.route("/assets", methods=["POST"])
@require_roles(ADMIN, service=SERVICE)
def add_asset():
    data = get_json_body()
    required = ["asset_name", "asset_type", "ip_address", "department", "owner_id", "criticality_level"]
    reject_unknown_fields(data, required + ["operating_system", "location", "status"])
    require_fields(data, required)
    _validate_asset(data)

    asset = assets.insert({k: clean_str(v) for k, v in data.items()})
    write_log(g.current_user["user_id"], "ASSET_CREATED",
              f"Asset '{asset.asset_name}' ({asset.asset_type}, {asset.criticality_level}) created",
              "Information", SERVICE)
    return success("Asset created successfully", asset.to_dict(), 201)


# ---------------------------------------------------------------- 2. Update Asset Information (Maya Zeaiter)
@assets_bp.route("/assets/<int:asset_id>", methods=["PUT"])
@require_roles(ADMIN, service=SERVICE)
def update_asset(asset_id):
    data = get_json_body()
    reject_unknown_fields(data, ["asset_name", "owner_id", "department", "criticality_level", "status",
                                 "asset_type", "ip_address", "operating_system", "location"])
    _validate_asset(data)

    before = assets.get_by_id(asset_id)
    if before is None:
        raise ApiError(f"Asset with id {asset_id} not found", 404)
    after = assets.update(asset_id, {k: clean_str(v) for k, v in data.items()})
    write_log(g.current_user["user_id"], "ASSET_UPDATED",
              f"Asset {asset_id} '{after.asset_name}' updated fields: {', '.join(data)}", "Information", SERVICE)
    return success("Asset updated successfully", {"before": before.to_dict(), "after": after.to_dict()})


# ---------------------------------------------------------------- 3. Delete Asset (Maya Zeaiter)
@assets_bp.route("/assets/<int:asset_id>", methods=["DELETE"])
@require_roles(ADMIN, service=SERVICE)
def delete_asset(asset_id):
    asset = assets.get_by_id(asset_id)
    if asset is None:
        raise ApiError(f"Asset with id {asset_id} not found", 404)
    assets.delete(asset_id)
    write_log(g.current_user["user_id"], "ASSET_DELETED", f"Asset {asset_id} '{asset.asset_name}' deleted",
              "Warning", SERVICE)
    return success(f"Asset '{asset.asset_name}' deleted successfully", {"deleted_asset_id": asset_id})


# ---------------------------------------------------------------- 4. Retrieve All Assets (Maya Zeaiter)
@assets_bp.route("/assets", methods=["GET"])
@require_roles(ADMIN, AUDITOR, service=SERVICE)
def get_all_assets():
    all_assets = [a.to_dict() for a in assets.get_all()]
    return success(f"{len(all_assets)} asset(s) found", {"count": len(all_assets), "assets": all_assets})


# ---------------------------------------------------------------- 5. Retrieve Specific Asset (Maya Zeaiter)
@assets_bp.route("/assets/<int:asset_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, service=SERVICE)
def get_asset(asset_id):
    asset = assets.get_by_id(asset_id)
    if asset is None:
        raise ApiError(f"Asset with id {asset_id} not found", 404)
    return success("Asset found", _with_relations(asset))


# ---------------------------------------------------------------- 6. Search Assets (Maya Zeaiter)
@assets_bp.route("/assets/search", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, service=SERVICE)
def search_assets():
    # query parameter -> (column, exact match?)
    criteria = {
        "name": ("asset_name", False),
        "type": ("asset_type", True),
        "ip": ("ip_address", False),
        "department": ("department", False),
        "criticality": ("criticality_level", True),
        "status": ("status", True),
    }
    unknown = sorted(set(request.args) - set(criteria))
    if unknown:
        raise ApiError("Unknown search parameters", 400,
                       {p: f"Allowed parameters: {', '.join(criteria)}" for p in unknown})
    if not request.args:
        raise ApiError(f"Provide at least one search parameter: {', '.join(criteria)}", 400)

    errors = {}
    check_choice(errors, request.args, "type", ASSET_TYPES)
    check_choice(errors, request.args, "criticality", CRITICALITY_LEVELS)
    check_choice(errors, request.args, "status", ASSET_STATUSES)
    raise_if_errors(errors)

    exact, partial = {}, {}
    for param, value in request.args.items():
        column, is_exact = criteria[param]
        (exact if is_exact else partial)[column] = value.strip()

    results = [a.to_dict() for a in assets.search(exact, partial)]
    return success(f"{len(results)} asset(s) match the search",
                   {"criteria": dict(request.args), "count": len(results), "assets": results})
