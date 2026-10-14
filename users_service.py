# Service 1: Users and Identity Management Service
# Maya Zeaiter
from flask import Blueprint, g, request
from werkzeug.security import check_password_hash, generate_password_hash

from common import (ADMIN, AUDITOR, REGULAR, ROLES, ApiError, _load_user_from_token, deny, generate_token,
                    get_json_body, require_roles, success, write_log)
from models import UserRepository
from validators import (check_choice, check_email, check_password, check_string, check_username, clean_str,
                        raise_if_errors, reject_unknown_fields, require_fields)

SERVICE = "Users and Identity Management"
ACCOUNT_STATUSES = ["Active", "Inactive", "Suspended"]

users_bp = Blueprint("users", __name__)
users = UserRepository()


def _optional_current_user():
    """Registration is public, but an admin token unlocks registering privileged roles."""
    if "Authorization" not in request.headers:
        return None
    return _load_user_from_token()


# ---------------------------------------------------------------- 1. User Registration (Maya Zeaiter)
@users_bp.route("/users/register", methods=["POST"])
def register_user():
    data = get_json_body()
    fields = ["full_name", "username", "email", "password", "department", "role"]
    reject_unknown_fields(data, fields + ["account_status"])
    require_fields(data, fields)

    errors = {}
    for f in ("full_name", "department"):
        check_string(errors, data, f, 100)
    check_username(errors, data)
    check_email(errors, data)
    check_password(errors, data)
    check_choice(errors, data, "role", ROLES)
    check_choice(errors, data, "account_status", ACCOUNT_STATUSES)
    raise_if_errors(errors)

    caller = _optional_current_user()
    is_admin = caller is not None and caller["role"] == ADMIN
    if not is_admin and (data["role"] != REGULAR or "account_status" in data):
        raise ApiError(f"Only a Security Administrator can register a '{data['role']}' account "
                       "or set the account status", 403)

    username = clean_str(data["username"])
    email = clean_str(data["email"]).lower()
    if users.is_taken("username", username):
        raise ApiError(f"Username '{username}' is already taken", 409)
    if users.is_taken("email", email):
        raise ApiError(f"Email '{email}' is already registered", 409)

    user = users.insert({
        "full_name": clean_str(data["full_name"]),
        "username": username,
        "email": email,
        "password_hash": generate_password_hash(data["password"]),
        "department": clean_str(data["department"]),
        "role": data["role"],
        "account_status": data.get("account_status", "Active"),
    })
    actor = caller["user_id"] if caller else user.user_id
    write_log(actor, "USER_CREATED", f"User '{user.username}' registered with role '{user.role}'",
              "Information", SERVICE)
    return success("User registered successfully", user.to_dict(), 201)


# ---------------------------------------------------------------- 2. User Login (Maya Zeaiter)
@users_bp.route("/users/login", methods=["POST"])
def login():
    data = get_json_body()
    require_fields(data, ["username", "password"])
    identifier = clean_str(data["username"])
    if not isinstance(identifier, str) or not isinstance(data["password"], str):
        raise ApiError("Username and password must be strings", 400)

    user = users.get_by_username_or_email(identifier)
    if user is None or not check_password_hash(user.password_hash, data["password"]):
        write_log(user.user_id if user else None, "LOGIN_FAILED",
                  f"Failed login attempt for '{identifier}'", "Warning", SERVICE)
        raise ApiError("Invalid username/email or password", 401)

    if user.account_status != "Active":
        write_log(user.user_id, "LOGIN_FAILED",
                  f"Login blocked for '{user.username}': account is {user.account_status}", "Warning", SERVICE)
        raise ApiError(f"Account is {user.account_status}. Contact a Security Administrator", 403)

    users.touch_last_login(user.user_id)
    write_log(user.user_id, "LOGIN_SUCCESS", f"User '{user.username}' logged in", "Information", SERVICE)
    user = users.get_by_id(user.user_id)
    return success("Authentication successful", {
        "token": generate_token(user.to_dict()),
        "token_type": "Bearer",
        "expires_in_seconds": 8 * 60 * 60,
        "user": user.to_dict(),
    })


# ---------------------------------------------------------------- 3. Update User Information (Maya Zeaiter)
@users_bp.route("/users/<int:user_id>", methods=["PUT"])
@require_roles(ADMIN, REGULAR, service=SERVICE)
def update_user(user_id):
    caller = g.current_user
    if caller["role"] == REGULAR and caller["user_id"] != user_id:
        deny("Regular users can only update their own information", SERVICE)

    data = get_json_body()
    allowed = ["full_name", "email", "department"]
    if caller["role"] == ADMIN:
        allowed += ["role", "account_status"]
    reject_unknown_fields(data, allowed)

    errors = {}
    for f in ("full_name", "department"):
        check_string(errors, data, f, 100)
    check_email(errors, data)
    check_choice(errors, data, "role", ROLES)
    check_choice(errors, data, "account_status", ACCOUNT_STATUSES)
    raise_if_errors(errors)

    before = users.get_by_id(user_id)
    if before is None:
        raise ApiError(f"User with id {user_id} not found", 404)

    values = {k: clean_str(v) for k, v in data.items()}
    if "email" in values:
        values["email"] = values["email"].lower()
        if users.is_taken("email", values["email"], exclude_id=user_id):
            raise ApiError(f"Email '{values['email']}' is already registered", 409)

    after = users.update(user_id, values)
    write_log(caller["user_id"], "USER_UPDATED",
              f"User '{after.username}' updated fields: {', '.join(values)}", "Information", SERVICE)
    if "role" in values and values["role"] != before.role:
        write_log(caller["user_id"], "ROLE_CHANGED",
                  f"Role of '{after.username}' changed from '{before.role}' to '{after.role}'", "Warning", SERVICE)
    return success("User updated successfully", {"before": before.to_dict(), "after": after.to_dict()})


# ---------------------------------------------------------------- 4. Delete User (Maya Zeaiter)
@users_bp.route("/users/<int:user_id>", methods=["DELETE"])
@require_roles(ADMIN, service=SERVICE)
def delete_user(user_id):
    caller = g.current_user
    if caller["user_id"] == user_id:
        raise ApiError("Administrators cannot delete their own account", 400)
    user = users.get_by_id(user_id)
    if user is None:
        raise ApiError(f"User with id {user_id} not found", 404)

    users.delete(user_id)  # FK violations (owned assets, reported incidents) -> 409 in app.py
    write_log(caller["user_id"], "USER_DELETED", f"User '{user.username}' (id {user_id}) deleted",
              "Warning", SERVICE)
    return success(f"User '{user.username}' deleted successfully", {"deleted_user_id": user_id})


# ---------------------------------------------------------------- 5. Retrieve All Users (Maya Zeaiter)
@users_bp.route("/users", methods=["GET"])
@require_roles(ADMIN, AUDITOR, service=SERVICE)
def get_all_users():
    all_users = [u.to_dict() for u in users.get_all()]
    return success(f"{len(all_users)} user(s) found", {"count": len(all_users), "users": all_users})


# ---------------------------------------------------------------- 6. Retrieve User By Username (Maya Zeaiter)
@users_bp.route("/users/<string:username>", methods=["GET"])
@require_roles(ADMIN, AUDITOR, REGULAR, service=SERVICE)
def get_user_by_username(username):
    caller = g.current_user
    if caller["role"] == REGULAR and caller["username"] != username:
        deny("Regular users can only view their own information", SERVICE)
    user = users.get_by_username(username)
    if user is None:
        raise ApiError(f"User '{username}' not found", 404)
    return success("User found", user.to_dict())
