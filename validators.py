# Input validation and sanitization helpers
# Maya Zeaiter
import ipaddress
import re
from datetime import datetime

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


# ---------------------------------------------------------------- threat indicators (Zeinab Harb)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$")
HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def normalize_threat_value(threat_type, value):
    """Validate the value against its type and return its canonical form.

    Returns (normalized_value, error_message). Canonical forms make duplicates detectable:
    IPs are compressed ("2001:DB8::0001" -> "2001:db8::1"), domains and hashes are lowercased.
    """
    if not isinstance(value, str):
        return None, "Must be a string"
    if not value.strip():
        return None, "This field is required"
    value = value.strip()
    if threat_type == "IP Address":
        try:
            return str(ipaddress.ip_address(value)), None
        except ValueError:
            return None, "Invalid IP address format (expected IPv4 like 185.220.101.4 or IPv6)"
    if threat_type == "Domain":
        domain = value.lower().rstrip(".")
        if not DOMAIN_RE.match(domain):
            return None, "Invalid domain format (expected something like malicious-site.com)"
        return domain, None
    if threat_type == "File Hash":
        if not HEX_RE.match(value) or len(value) not in HASH_LENGTHS:
            return None, ("Invalid hash format: must be hexadecimal MD5 (32), SHA-1 (40), "
                          "SHA-256 (64) or SHA-512 (128) characters")
        return value.lower(), None
    if len(value) > 255:
        return None, "Must be at most 255 characters"
    return value, None


def check_date(errors, data, field):
    """YYYY-MM-DD calendar date (used to search logs by day)."""
    value = data.get(field)
    if value is None:
        return
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except (TypeError, ValueError):
        errors[field] = "Invalid date. Use the format YYYY-MM-DD"


# ---------------------------------------------------------------- vulnerabilities, notifications, playbooks (Omar Obeid)
CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
DATETIME_FORMATS = ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S")


def check_cve(errors, data, field="cve_identifier"):
    """CVE-YYYY-NNNN: 'CVE', a year from 1999 (first CVE list) to next year, then 4 or more digits."""
    value = data.get(field)
    if value is None:
        return
    if not isinstance(value, str):
        errors[field] = "Must be a string"
        return
    match = CVE_RE.match(value.strip().upper())
    if not match:
        errors[field] = "Invalid CVE format. Expected CVE-YYYY-NNNN (4 or more digits), e.g. CVE-2024-6387"
    elif not 1999 <= int(match.group(1)) <= datetime.utcnow().year + 1:
        errors[field] = f"Invalid CVE year {match.group(1)}"


def check_cvss(errors, data, field="cvss_score"):
    value = data.get(field)
    if value is None:
        return
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        errors[field] = "Must be a number between 0.0 and 10.0"
    elif not 0 <= value <= 10:
        errors[field] = "CVSS score must be between 0.0 and 10.0"
    elif round(value, 1) != value:
        errors[field] = "CVSS score has one decimal place (e.g. 7.5)"


def parse_datetime(errors, data, field):
    """Accept YYYY-MM-DD or YYYY-MM-DD HH:MM:SS (UTC); return the stored form, or None."""
    value = data.get(field)
    if value is None:
        return None
    for fmt in DATETIME_FORMATS:
        try:
            parsed = datetime.strptime(value, fmt) if isinstance(value, str) else None
        except ValueError:
            continue
        if parsed is not None:
            if parsed > datetime.utcnow():
                errors[field] = "Date cannot be in the future"
                return None
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
    errors[field] = "Invalid date. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS"
    return None
