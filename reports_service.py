# Service 6: Security Reports Service
# Zeinab Harb
#
# Reports are read-only aggregations over the shared database tables owned by the other services:
#   users (Service 1), assets (Service 2), incidents (Service 3), threats (Service 4),
#   logs (Service 5) and vulnerabilities (Service 7).
# Every group-by result lists all allowed values, including those with a count of 0, so the numbers can be
# checked directly against the database.
from datetime import datetime, timezone

from flask import Blueprint, g

from assets_service import ASSET_STATUSES, ASSET_TYPES, CRITICALITY_LEVELS
from common import ADMIN, AUDITOR, require_roles, set_developer, success
from database import connect_to_db
from incidents_service import CATEGORIES as INCIDENT_CATEGORIES
from models import AuditLog, Incident, Threat

DEVELOPER = "Zeinab Harb"
SERVICE = "Security Reports"
SEVERITIES = ["Low", "Medium", "High", "Critical"]
VULNERABILITY_STATUSES = ["Open", "Under Investigation", "In Progress", "Resolved", "Closed"]
CLOSED_STATES = ("Resolved", "Closed")  # anything else counts as still open
RECENT_LIMIT = 5
TOP_LIMIT = 5

reports_bp = Blueprint("reports", __name__)
set_developer(reports_bp, DEVELOPER)


# ---------------------------------------------------------------- query helpers
class ReportQueries:
    """Small read-only helper around one database connection. Table/column names are fixed in this file;
    user input never reaches these queries."""

    def __init__(self, conn):
        self.conn = conn

    def count(self, table, where="", params=()):
        sql = f"SELECT COUNT(*) FROM {table}" + (f" WHERE {where}" if where else "")
        return self.conn.execute(sql, params).fetchone()[0]

    def group(self, table, column, allowed):
        """{value: count} for every allowed value (0 when absent)."""
        result = {value: 0 for value in allowed}
        for row in self.conn.execute(f"SELECT {column}, COUNT(*) FROM {table} GROUP BY {column}"):
            result[row[0]] = row[1]
        return result

    def rows(self, sql, params=()):
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]


def _report(name, data):
    data = {"report": name,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "generated_by": g.current_user["username"],
            **data}
    return success(f"{name} generated successfully", data)


def _placeholders(values):
    return ", ".join("?" for _ in values)


# ---------------------------------------------------------------- 1. Generate Security Summary Report (Zeinab Harb)
@reports_bp.route("/reports/summary", methods=["GET"])
@require_roles(ADMIN, AUDITOR, service=SERVICE)
def summary_report():
    conn = connect_to_db()
    try:
        q = ReportQueries(conn)
        closed = _placeholders(CLOSED_STATES)
        data = {
            "users": q.count("users"),
            "active_users": q.count("users", "account_status = 'Active'"),
            "assets": q.count("assets"),
            "critical_assets": q.count("assets", "criticality_level = 'Critical'"),
            "incidents": q.count("incidents"),
            "open_incidents": q.count("incidents", f"status NOT IN ({closed})", CLOSED_STATES),
            "critical_open_incidents": q.count("incidents", f"severity = 'Critical' AND status NOT IN ({closed})",
                                               CLOSED_STATES),
            "threats": q.count("threats"),
            "critical_threats": q.count("threats", "severity_level = 'Critical'"),
            "vulnerabilities": q.count("vulnerabilities"),
            "open_vulnerabilities": q.count("vulnerabilities", f"status NOT IN ({closed})", CLOSED_STATES),
            "audit_log_records": q.count("logs"),
            "failed_logins": q.count("logs", "action_performed = 'LOGIN_FAILED'"),
            "unauthorized_access_attempts": q.count("logs", "action_performed = 'UNAUTHORIZED_ACCESS'"),
            "recent_security_activities": q.rows(
                "SELECT l.log_id, l.timestamp, u.username, l.action_performed, l.severity_level, l.related_service "
                "FROM logs l LEFT JOIN users u ON u.user_id = l.user_id ORDER BY l.log_id DESC LIMIT ?",
                (RECENT_LIMIT,)),
        }
    finally:
        conn.close()
    return _report("Security Summary Report", data)


# ---------------------------------------------------------------- 2. Generate Incident Report (Zeinab Harb)
@reports_bp.route("/reports/incidents", methods=["GET"])
@require_roles(ADMIN, AUDITOR, service=SERVICE)
def incident_report():
    conn = connect_to_db()
    try:
        q = ReportQueries(conn)
        closed = _placeholders(CLOSED_STATES)
        data = {
            "total_incidents": q.count("incidents"),
            "open_incidents": q.count("incidents", f"status NOT IN ({closed})", CLOSED_STATES),
            "unassigned_incidents": q.count("incidents", "assigned_analyst_id IS NULL"),
            "incidents_by_severity": q.group("incidents", "severity", SEVERITIES),
            "incidents_by_status": q.group("incidents", "status", Incident.STATUS_FLOW),
            "incidents_by_category": q.group("incidents", "category", INCIDENT_CATEGORIES),
            "recent_incidents": q.rows(
                "SELECT incident_id, title, severity, status, creation_date FROM incidents "
                "ORDER BY incident_id DESC LIMIT ?", (RECENT_LIMIT,)),
        }
    finally:
        conn.close()
    return _report("Incident Report", data)


# ---------------------------------------------------------------- 3. Generate Asset Report (Zeinab Harb)
@reports_bp.route("/reports/assets", methods=["GET"])
@require_roles(ADMIN, AUDITOR, service=SERVICE)
def asset_report():
    conn = connect_to_db()
    try:
        q = ReportQueries(conn)
        data = {
            "total_assets": q.count("assets"),
            "critical_assets": q.count("assets", "criticality_level = 'Critical'"),
            "critical_asset_list": q.rows(
                "SELECT asset_id, asset_name, asset_type, ip_address, status FROM assets "
                "WHERE criticality_level = 'Critical' ORDER BY asset_id"),
            "assets_by_type": q.group("assets", "asset_type", ASSET_TYPES),
            "assets_by_criticality": q.group("assets", "criticality_level", CRITICALITY_LEVELS),
            "assets_by_status": q.group("assets", "status", ASSET_STATUSES),
        }
    finally:
        conn.close()
    return _report("Asset Report", data)


# ---------------------------------------------------------------- 4. Generate Threat Report (Zeinab Harb)
@reports_bp.route("/reports/threats", methods=["GET"])
@require_roles(ADMIN, AUDITOR, service=SERVICE)
def threat_report():
    conn = connect_to_db()
    try:
        q = ReportQueries(conn)
        data = {
            "total_threats": q.count("threats"),
            "threats_by_severity": q.group("threats", "severity_level", Threat.SEVERITIES),
            "threats_by_type": q.group("threats", "threat_type", Threat.TYPES),
            "recently_added_threats": q.rows(
                "SELECT threat_id, threat_type, threat_value, severity_level, source, date_added FROM threats "
                "ORDER BY date_added DESC, threat_id DESC LIMIT ?", (RECENT_LIMIT,)),
        }
    finally:
        conn.close()
    return _report("Threat Report", data)


# ---------------------------------------------------------------- 5. Generate Vulnerability Report (Zeinab Harb)
@reports_bp.route("/reports/vulnerabilities", methods=["GET"])
@require_roles(ADMIN, AUDITOR, service=SERVICE)
def vulnerability_report():
    conn = connect_to_db()
    try:
        q = ReportQueries(conn)
        average = conn.execute("SELECT AVG(cvss_score) FROM vulnerabilities").fetchone()[0]
        data = {
            "total_vulnerabilities": q.count("vulnerabilities"),
            "vulnerabilities_by_severity": q.group("vulnerabilities", "severity_level", SEVERITIES),
            "vulnerabilities_by_status": q.group("vulnerabilities", "status", VULNERABILITY_STATUSES),
            "critical_vulnerabilities": q.count("vulnerabilities", "severity_level = 'Critical'"),
            "critical_vulnerability_list": q.rows(
                "SELECT v.vulnerability_id, v.title, v.cve_identifier, v.cvss_score, v.status, "
                "v.affected_asset_id, a.asset_name AS affected_asset_name "
                "FROM vulnerabilities v LEFT JOIN assets a ON a.asset_id = v.affected_asset_id "
                "WHERE v.severity_level = 'Critical' ORDER BY v.cvss_score DESC, v.vulnerability_id"),
            "average_cvss_score": round(average, 2) if average is not None else None,
        }
    finally:
        conn.close()
    return _report("Vulnerability Report", data)


# ---------------------------------------------------------------- 6. Generate Activity Report (Zeinab Harb)
@reports_bp.route("/reports/activity", methods=["GET"])
@require_roles(ADMIN, AUDITOR, service=SERVICE)
def activity_report():
    conn = connect_to_db()
    try:
        q = ReportQueries(conn)
        successful = q.count("logs", "action_performed = 'LOGIN_SUCCESS'")
        failed = q.count("logs", "action_performed = 'LOGIN_FAILED'")
        data = {
            "total_user_activities": q.count("logs"),
            "login_attempts": successful + failed,
            "successful_logins": successful,
            "failed_login_attempts": failed,
            "unauthorized_access_attempts": q.count("logs", "action_performed = 'UNAUTHORIZED_ACCESS'"),
            "most_performed_actions": q.rows(
                "SELECT action_performed AS action, COUNT(*) AS count FROM logs "
                "GROUP BY action_performed ORDER BY count DESC, action LIMIT ?", (TOP_LIMIT,)),
            "most_active_users": q.rows(
                "SELECT l.user_id, u.username, COUNT(*) AS activities FROM logs l "
                "LEFT JOIN users u ON u.user_id = l.user_id WHERE l.user_id IS NOT NULL "
                "GROUP BY l.user_id ORDER BY activities DESC, l.user_id LIMIT ?", (TOP_LIMIT,)),
            "activities_by_severity": q.group("logs", "severity_level", AuditLog.SEVERITIES),
            "activities_by_service": q.rows(
                "SELECT related_service AS service, COUNT(*) AS count FROM logs "
                "GROUP BY related_service ORDER BY count DESC, service"),
        }
    finally:
        conn.close()
    return _report("Activity Report", data)
