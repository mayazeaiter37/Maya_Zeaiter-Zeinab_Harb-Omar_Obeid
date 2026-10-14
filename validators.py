# Input validation and sanitization helpers
# Maya Zeaiter
import ipaddress
import re

from common import ApiError

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{3,30}$")


def clean_str(value):
    """Strip whitespace; non-strings are rejected by the caller's checks."""
    return value.strip() if isinstance(value, str) else value


def require_fields(data, fields):
    missing = [f for f in fields if f not in data or data[f] is None or
               (isinstance(data[f], str) and not data[f].strip())]
    if missing:
        raise ApiError("Missing required fields", 400, {f: "This field is required" for f in missing})


def reject_unknown_fields(data, allowed):
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise ApiError("Unexpected fields in request", 400, {f: "Field is not allowed here" for f in unknown})


def check_string(errors, data, field, max_len=255):
    value = data.get(field)
    if value is None:
        return
    if not isinstance(value, str):
        errors[field] = "Must be a string"
    elif len(value.strip()) == 0:
        errors[field] = "Cannot be empty"
    elif len(value) > max_len:
        errors[field] = f"Must be at most {max_len} characters"


def check_choice(errors, data, field, choices):
    value = data.get(field)
    if value is not None and value not in choices:
        errors[field] = f"Invalid value '{value}'. Allowed: {', '.join(choices)}"


def check_int(errors, data, field):
    value = data.get(field)
    if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value <= 0):
        errors[field] = "Must be a positive integer"


def check_email(errors, data, field="email"):
    value = data.get(field)
    if isinstance(value, str) and not EMAIL_RE.match(value.strip()):
        errors[field] = "Invalid email format"


def check_username(errors, data, field="username"):
    value = data.get(field)
    if isinstance(value, str) and not USERNAME_RE.match(value.strip()):
        errors[field] = "Username must be 3-30 characters: letters, digits, '_' or '.'"


def check_password(errors, data, field="password"):
    value = data.get(field)
    if not isinstance(value, str):
        return
    problems = []
    if len(value) < 8:
        problems.append("at least 8 characters")
    if not re.search(r"[A-Z]", value):
        problems.append("an uppercase letter")
    if not re.search(r"[a-z]", value):
        problems.append("a lowercase letter")
    if not re.search(r"\d", value):
        problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", value):
        problems.append("a special character")
    if problems:
        errors[field] = "Password must contain " + ", ".join(problems)


def check_ip(errors, data, field="ip_address"):
    value = data.get(field)
    if isinstance(value, str):
        try:
            ipaddress.ip_address(value.strip())
        except ValueError:
            errors[field] = "Invalid IP address format"


def raise_if_errors(errors):
    if errors:
        raise ApiError("Validation failed", 400, errors)
