# Entity classes and repositories for Users, Assets, Incidents and Investigation Notes
# Maya Zeaiter
from dataclasses import asdict, dataclass, field
from typing import List, Optional

from database import connect_to_db


# ---------------------------------------------------------------- entities
@dataclass
class User:
    user_id: int
    full_name: str
    username: str
    email: str
    password_hash: str
    department: str
    role: str
    account_status: str
    created_date: str
    last_login_date: Optional[str]

    def to_dict(self):
        data = asdict(self)
        data.pop("password_hash")  # never returned by the API
        return data


@dataclass
class Asset:
    asset_id: int
    asset_name: str
    asset_type: str
    ip_address: str
    operating_system: Optional[str]
    owner_id: int
    department: str
    location: Optional[str]
    criticality_level: str
    status: str
    created_date: str

    def to_dict(self):
        return asdict(self)


@dataclass
class InvestigationNote:
    note_id: int
    incident_id: int
    analyst_id: int
    note_content: str
    creation_timestamp: str

    def to_dict(self):
        return asdict(self)


@dataclass
class Incident:
    STATUS_FLOW = ["Open", "Under Investigation", "Mitigated", "Resolved", "Closed"]

    incident_id: int
    title: str
    description: str
    category: str
    severity: str
    reporter_id: int
    asset_id: Optional[int]
    assigned_analyst_id: Optional[int]
    status: str
    creation_date: str
    resolution_date: Optional[str]
    notes: List[InvestigationNote] = field(default_factory=list)

    def next_status(self):
        """The only status this incident may move to, or None if already Closed."""
        index = self.STATUS_FLOW.index(self.status)
        return self.STATUS_FLOW[index + 1] if index + 1 < len(self.STATUS_FLOW) else None

    def can_transition_to(self, new_status):
        return new_status == self.next_status()

    def to_dict(self):
        data = asdict(self)
        data["notes"] = [n.to_dict() for n in self.notes]
        return data


# ---------------------------------------------------------------- repositories
class BaseRepository:
    """Shared CRUD plumbing. Subclasses set table, pk, entity and the searchable columns."""

    table = ""
    pk = ""
    entity = None

    def _query(self, sql, params=()):
        conn = connect_to_db()
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def _execute(self, sql, params=()):
        conn = connect_to_db()
        try:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur
        finally:
            conn.close()

    def _to_entity(self, row):
        return self.entity(**dict(row)) if row is not None else None

    def get_by_id(self, record_id):
        rows = self._query(f"SELECT * FROM {self.table} WHERE {self.pk} = ?", (record_id,))
        return self._to_entity(rows[0]) if rows else None

    def get_all(self):
        return [self._to_entity(r) for r in self._query(f"SELECT * FROM {self.table} ORDER BY {self.pk}")]

    def insert(self, values):
        columns = ", ".join(values)
        placeholders = ", ".join("?" for _ in values)
        cur = self._execute(f"INSERT INTO {self.table} ({columns}) VALUES ({placeholders})", tuple(values.values()))
        return self.get_by_id(cur.lastrowid)

    def update(self, record_id, values):
        if values:
            assignments = ", ".join(f"{col} = ?" for col in values)
            self._execute(f"UPDATE {self.table} SET {assignments} WHERE {self.pk} = ?",
                          tuple(values.values()) + (record_id,))
        return self.get_by_id(record_id)

    def delete(self, record_id):
        return self._execute(f"DELETE FROM {self.table} WHERE {self.pk} = ?", (record_id,)).rowcount > 0

    def search(self, exact=None, partial=None):
        """Parameterised filter: exact {column: value} matches and partial (LIKE) matches."""
        clauses, params = [], []
        for column, value in (exact or {}).items():
            clauses.append(f"{column} = ?")
            params.append(value)
        for column, value in (partial or {}).items():
            clauses.append(f"{column} LIKE ? COLLATE NOCASE")
            params.append(f"%{value}%")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self._query(f"SELECT * FROM {self.table}{where} ORDER BY {self.pk}", tuple(params))
        return [self._to_entity(r) for r in rows]


class UserRepository(BaseRepository):
    table, pk, entity = "users", "user_id", User

    def get_by_username(self, username):
        rows = self._query("SELECT * FROM users WHERE username = ?", (username,))
        return self._to_entity(rows[0]) if rows else None

    def get_by_username_or_email(self, identifier):
        rows = self._query("SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier))
        return self._to_entity(rows[0]) if rows else None

    def is_taken(self, column, value, exclude_id=None):
        rows = self._query(f"SELECT user_id FROM users WHERE {column} = ? COLLATE NOCASE AND user_id != ?",
                           (value, exclude_id or 0))
        return bool(rows)

    def touch_last_login(self, user_id):
        self._execute("UPDATE users SET last_login_date = datetime('now') WHERE user_id = ?", (user_id,))


class AssetRepository(BaseRepository):
    table, pk, entity = "assets", "asset_id", Asset

    def has_incidents(self, asset_id):
        return bool(self._query("SELECT 1 FROM incidents WHERE asset_id = ? LIMIT 1", (asset_id,)))


class NoteRepository(BaseRepository):
    table, pk, entity = "investigation_notes", "note_id", InvestigationNote

    def for_incident(self, incident_id):
        rows = self._query("SELECT * FROM investigation_notes WHERE incident_id = ? ORDER BY note_id",
                           (incident_id,))
        return [self._to_entity(r) for r in rows]


class IncidentRepository(BaseRepository):
    table, pk, entity = "incidents", "incident_id", Incident

    def __init__(self):
        self.notes = NoteRepository()

    def get_by_id(self, record_id, with_notes=True):
        incident = super().get_by_id(record_id)
        if incident and with_notes:
            incident.notes = self.notes.for_incident(record_id)
        return incident


# ---------------------------------------------------------------- Services 4-5 entities (Zeinab Harb)
@dataclass
class Threat:
    """A threat-intelligence indicator (malicious IP, domain, file hash, ...). (Zeinab Harb)"""

    TYPES = ["IP Address", "Domain", "File Hash", "Malware Signature", "Other"]
    SEVERITIES = ["Low", "Medium", "High", "Critical"]

    threat_id: int
    threat_type: str
    threat_value: str
    description: str
    severity_level: str
    source: str
    date_added: str

    def to_dict(self):
        return asdict(self)


@dataclass
class AuditLog:
    """One security audit record. Logs are append-only: there is no update method. (Zeinab Harb)"""

    SEVERITIES = ["Information", "Warning", "Error", "Critical"]

    log_id: int
    user_id: Optional[int]
    action_performed: str
    description: str
    timestamp: str
    severity_level: str
    related_service: str

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------- Services 4-5 repositories (Zeinab Harb)
class ThreatRepository(BaseRepository):
    table, pk, entity = "threats", "threat_id", Threat

    def find_duplicate(self, threat_type, threat_value):
        """Existing indicator with the same type and value (case-insensitive), or None."""
        rows = self._query("SELECT * FROM threats WHERE threat_type = ? AND threat_value = ? COLLATE NOCASE",
                           (threat_type, threat_value))
        return self._to_entity(rows[0]) if rows else None


class LogRepository(BaseRepository):
    table, pk, entity = "logs", "log_id", AuditLog

    def update(self, record_id, values):
        raise NotImplementedError("Audit logs are append-only and cannot be modified")

    def get_all(self):
        """Newest first, which is how auditors read activity."""
        return [self._to_entity(r) for r in self._query("SELECT * FROM logs ORDER BY log_id DESC")]

    def for_user(self, user_id):
        rows = self._query("SELECT * FROM logs WHERE user_id = ? ORDER BY log_id DESC", (user_id,))
        return [self._to_entity(r) for r in rows]

    def filter(self, user_id=None, username=None, date=None, action=None, severity=None, service=None):
        """Combine any of the filters with AND. Every value is a bound parameter, never part of the SQL text."""
        clauses, params = [], []
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if username is not None:
            clauses.append("user_id IN (SELECT user_id FROM users WHERE username = ? COLLATE NOCASE)")
            params.append(username)
        if date is not None:
            clauses.append("date(timestamp) = ?")
            params.append(date)
        if action is not None:
            clauses.append("action_performed LIKE ? COLLATE NOCASE")
            params.append(f"%{action}%")
        if severity is not None:
            clauses.append("severity_level = ?")
            params.append(severity)
        if service is not None:
            clauses.append("related_service LIKE ? COLLATE NOCASE")
            params.append(f"%{service}%")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self._query(f"SELECT * FROM logs{where} ORDER BY log_id DESC", tuple(params))
        return [self._to_entity(r) for r in rows]


# ---------------------------------------------------------------- Services 7-9 entities (Omar Obeid)
@dataclass
class Vulnerability:
    """A known weakness (CVE) on an asset. Its status only moves forward through STATUS_FLOW. (Omar Obeid)"""

    STATUS_FLOW = ["Open", "Under Investigation", "In Progress", "Resolved", "Closed"]
    SEVERITIES = ["Low", "Medium", "High", "Critical"]

    vulnerability_id: int
    title: str
    description: str
    cve_identifier: str
    cvss_score: float
    severity_level: str
    affected_asset_id: int
    discovery_source: str
    status: str
    creation_date: str
    resolution_date: Optional[str]

    @staticmethod
    def severity_for_score(score):
        """CVSS v3 qualitative rating: 0.0-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical."""
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"

    def next_status(self):
        index = self.STATUS_FLOW.index(self.status)
        return self.STATUS_FLOW[index + 1] if index + 1 < len(self.STATUS_FLOW) else None

    def can_transition_to(self, new_status):
        return new_status == self.next_status()

    def to_dict(self):
        return asdict(self)


@dataclass
class Notification:
    """A message delivered to one user. Starts Unread; read_date is set when the user reads it. (Omar Obeid)"""

    TYPES = ["Incident Assignment", "Security Alert", "System Notification", "Threat Alert", "Vulnerability Alert"]
    SEVERITIES = ["Low", "Medium", "High", "Critical"]
    STATUSES = ["Unread", "Read"]

    notification_id: int
    user_id: int
    title: str
    message: str
    notification_type: str
    severity_level: str
    status: str
    creation_date: str
    read_date: Optional[str]

    def to_dict(self):
        return asdict(self)


@dataclass
class ResponseAction:
    """One numbered step of a playbook. Pending -> In Progress -> Completed. (Omar Obeid)"""

    STATUS_FLOW = ["Pending", "In Progress", "Completed"]

    action_id: int
    playbook_id: int
    action_description: str
    step_number: int
    status: str
    assigned_user_id: Optional[int]
    completion_date: Optional[str]

    def next_status(self):
        index = self.STATUS_FLOW.index(self.status)
        return self.STATUS_FLOW[index + 1] if index + 1 < len(self.STATUS_FLOW) else None

    def can_transition_to(self, new_status):
        return new_status == self.next_status()

    def to_dict(self):
        return asdict(self)


@dataclass
class Playbook:
    """A predefined incident response procedure made of ordered ResponseActions. (Omar Obeid)"""

    SEVERITIES = ["Low", "Medium", "High", "Critical"]

    playbook_id: int
    playbook_name: str
    description: str
    incident_category: str
    severity_level: str
    created_by: Optional[int]
    creation_date: str
    actions: List[ResponseAction] = field(default_factory=list)

    def progress(self):
        done = sum(1 for a in self.actions if a.status == "Completed")
        return {"total_steps": len(self.actions), "completed_steps": done,
                "percent_complete": round(100 * done / len(self.actions)) if self.actions else 0}

    def to_dict(self):
        data = asdict(self)
        data["actions"] = [a.to_dict() for a in self.actions]
        data["progress"] = self.progress()
        return data


# ---------------------------------------------------------------- Services 7-9 repositories (Omar Obeid)
class VulnerabilityRepository(BaseRepository):
    table, pk, entity = "vulnerabilities", "vulnerability_id", Vulnerability

    def find_duplicate(self, cve_identifier, asset_id):
        """The same CVE already recorded on the same asset, or None."""
        rows = self._query("SELECT * FROM vulnerabilities WHERE cve_identifier = ? COLLATE NOCASE "
                           "AND affected_asset_id = ?", (cve_identifier, asset_id))
        return self._to_entity(rows[0]) if rows else None


class NotificationRepository(BaseRepository):
    table, pk, entity = "notifications", "notification_id", Notification

    def get_all(self):
        """Newest first, like an inbox."""
        return [self._to_entity(r) for r in self._query("SELECT * FROM notifications ORDER BY notification_id DESC")]

    def for_user(self, user_id):
        rows = self._query("SELECT * FROM notifications WHERE user_id = ? ORDER BY notification_id DESC", (user_id,))
        return [self._to_entity(r) for r in rows]

    def filter(self, user_id=None, username=None, notification_type=None, severity=None, status=None):
        """Combine any of the filters with AND; every value is a bound parameter."""
        clauses, params = [], []
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if username is not None:
            clauses.append("user_id IN (SELECT user_id FROM users WHERE username = ? COLLATE NOCASE)")
            params.append(username)
        for column, value in (("notification_type", notification_type), ("severity_level", severity),
                              ("status", status)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self._query(f"SELECT * FROM notifications{where} ORDER BY notification_id DESC", tuple(params))
        return [self._to_entity(r) for r in rows]

    def mark_read(self, notification_id):
        self._execute("UPDATE notifications SET status = 'Read', read_date = datetime('now') "
                      "WHERE notification_id = ?", (notification_id,))
        return self.get_by_id(notification_id)


class ActionRepository(BaseRepository):
    table, pk, entity = "response_actions", "action_id", ResponseAction

    def for_playbook(self, playbook_id):
        rows = self._query("SELECT * FROM response_actions WHERE playbook_id = ? ORDER BY step_number",
                           (playbook_id,))
        return [self._to_entity(r) for r in rows]

    def step_taken(self, playbook_id, step_number):
        return bool(self._query("SELECT 1 FROM response_actions WHERE playbook_id = ? AND step_number = ?",
                                (playbook_id, step_number)))

    def unfinished_before(self, playbook_id, step_number):
        """Earlier steps of the playbook that are not Completed yet."""
        rows = self._query("SELECT * FROM response_actions WHERE playbook_id = ? AND step_number < ? "
                           "AND status != 'Completed' ORDER BY step_number", (playbook_id, step_number))
        return [self._to_entity(r) for r in rows]


class PlaybookRepository(BaseRepository):
    table, pk, entity = "playbooks", "playbook_id", Playbook

    def __init__(self):
        self.actions = ActionRepository()

    def get_by_id(self, record_id, with_actions=True):
        playbook = super().get_by_id(record_id)
        if playbook and with_actions:
            playbook.actions = self.actions.for_playbook(record_id)
        return playbook

    def get_all(self):
        playbooks = super().get_all()
        for playbook in playbooks:
            playbook.actions = self.actions.for_playbook(playbook.playbook_id)
        return playbooks

    def find_by_name(self, name):
        rows = self._query("SELECT * FROM playbooks WHERE playbook_name = ? COLLATE NOCASE", (name,))
        return self._to_entity(rows[0]) if rows else None
