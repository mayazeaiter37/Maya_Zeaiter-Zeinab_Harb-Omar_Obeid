# Shared helpers: JSON responses, API errors, audit logging, token auth and role checks
# Maya Zeaiter
from functools import wraps

from flask import current_app, g, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from database import connect_to_db

STUDENT_NAME = "Maya Zeaiter"
TOKEN_MAX_AGE_SECONDS = 60 * 60 * 8  # 8 hours

ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
REGULAR = "Regular User"
AUDITOR = "Auditor"
ROLES = [ADMIN, ANALYST, REGULAR, AUDITOR]


# ---------------------------------------------------------------- responses / errors
class ApiError(Exception):
    """Raised anywhere in a request; turned into {"status": "error", ...} by app.py."""

    def __init__(self, message, status_code=400, errors=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.errors = errors


def success(message, data=None, status_code=200):
    body = {"status": "success", "message": message, "developer": STUDENT_NAME}
    if data is not None:
        body["data"] = data
    return jsonify(body), status_code


def error_body(message, errors=None):
    body = {"status": "error", "message": message, "developer": STUDENT_NAME}
    if errors:
        body["errors"] = errors
    return body


def get_json_body():
    """Reject empty / non-JSON bodies before any validation happens."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data:
        raise ApiError("Request body must be a non-empty JSON object", 400)
    return data


# ---------------------------------------------------------------- audit logging
def write_log(user_id, action, description, severity="Information", service="Users and Identity Management"):
    """Insert a record into the shared logs table (Security Audit Logging Service)."""
    conn = connect_to_db()
    try:
        conn.execute(
            "INSERT INTO logs (user_id, action_performed, description, severity_level, related_service) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, action, description, severity, service),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------- tokens
def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="auth-token")


def generate_token(user):
    return _serializer().dumps({"user_id": user["user_id"], "role": user["role"]})


def _load_user_from_token():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise ApiError("Missing authentication token. Send 'Authorization: Bearer <token>'", 401)
    token = header[len("Bearer "):].strip()
    try:
        payload = _serializer().loads(token, max_age=TOKEN_MAX_AGE_SECONDS)
    except SignatureExpired:
        raise ApiError("Authentication token has expired, please log in again", 401)
    except BadSignature:
        raise ApiError("Invalid authentication token", 401)

    conn = connect_to_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE user_id = ?", (payload["user_id"],)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise ApiError("User attached to this token no longer exists", 401)
    if row["account_status"] != "Active":
        raise ApiError(f"Account is {row['account_status']}; access denied", 403)
    return dict(row)


def require_roles(*allowed_roles, service="Users and Identity Management"):
    """Authenticate the caller, then check their role. Violations are written to the audit log."""

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            g.current_user = _load_user_from_token()
            role = g.current_user["role"]
            if role not in allowed_roles:
                write_log(
                    g.current_user["user_id"],
                    "UNAUTHORIZED_ACCESS",
                    f"{role} '{g.current_user['username']}' tried {request.method} {request.path}",
                    "Warning",
                    service,
                )
                raise ApiError("User does not have permission to perform this operation", 403)
            return view(*args, **kwargs)

        return wrapper

    return decorator


def deny(message, service):
    """Record a permission violation for checks that depend on the record (e.g. 'own data only')."""
    user = g.current_user
    write_log(user["user_id"], "UNAUTHORIZED_ACCESS",
              f"{user['role']} '{user['username']}' tried {request.method} {request.path}: {message}",
              "Warning", service)
    raise ApiError(message, 403)
