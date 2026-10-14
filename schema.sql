-- Security Incident Detection and Response Management System
-- Database schema (SQLite)
-- Users, Assets, Incidents, Investigation Notes: Maya Zeaiter
-- The remaining tables are created here so the shared database is complete;
-- their services are implemented by the other team members.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------- Users (Maya Zeaiter)
CREATE TABLE IF NOT EXISTS users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name       TEXT NOT NULL,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    department      TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('Security Administrator', 'Security Analyst',
                                                  'Regular User', 'Auditor')),
    account_status  TEXT NOT NULL DEFAULT 'Active'
                    CHECK (account_status IN ('Active', 'Inactive', 'Suspended')),
    created_date    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_date TEXT
);

-- ---------------------------------------------------------------- Assets (Maya Zeaiter)
CREATE TABLE IF NOT EXISTS assets (
    asset_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name        TEXT NOT NULL,
    asset_type        TEXT NOT NULL CHECK (asset_type IN ('Server', 'Workstation', 'Database',
                                                          'Application', 'Network Device', 'Cloud Resource')),
    ip_address        TEXT NOT NULL,
    operating_system  TEXT,
    owner_id          INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    department        TEXT NOT NULL,
    location          TEXT,
    criticality_level TEXT NOT NULL CHECK (criticality_level IN ('Low', 'Medium', 'High', 'Critical')),
    status            TEXT NOT NULL DEFAULT 'Active'
                      CHECK (status IN ('Active', 'Inactive', 'Under Maintenance')),
    created_date      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------- Incidents (Maya Zeaiter)
CREATE TABLE IF NOT EXISTS incidents (
    incident_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    reporter_id         INTEGER NOT NULL REFERENCES users(user_id),
    asset_id            INTEGER REFERENCES assets(asset_id) ON DELETE SET NULL,
    assigned_analyst_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    status              TEXT NOT NULL DEFAULT 'Open'
                        CHECK (status IN ('Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed')),
    creation_date       TEXT NOT NULL DEFAULT (datetime('now')),
    resolution_date     TEXT
);

-- ---------------------------------------------------------------- Investigation notes (Maya Zeaiter)
CREATE TABLE IF NOT EXISTS investigation_notes (
    note_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id        INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    analyst_id         INTEGER NOT NULL REFERENCES users(user_id),
    note_content       TEXT NOT NULL,
    creation_timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------- Threats (teammate)
CREATE TABLE IF NOT EXISTS threats (
    threat_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type    TEXT NOT NULL CHECK (threat_type IN ('IP Address', 'Domain', 'File Hash',
                                                        'Malware Signature', 'Other')),
    threat_value   TEXT NOT NULL,
    description    TEXT NOT NULL,
    severity_level TEXT NOT NULL CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    source         TEXT NOT NULL,
    date_added     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (threat_type, threat_value)
);

-- ---------------------------------------------------------------- Logs (teammate; written to by all services)
CREATE TABLE IF NOT EXISTS logs (
    log_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    action_performed TEXT NOT NULL,
    description      TEXT NOT NULL,
    timestamp        TEXT NOT NULL DEFAULT (datetime('now')),
    severity_level   TEXT NOT NULL CHECK (severity_level IN ('Information', 'Warning', 'Error', 'Critical')),
    related_service  TEXT NOT NULL
);

-- ---------------------------------------------------------------- Vulnerabilities (teammate)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    title             TEXT NOT NULL,
    description       TEXT NOT NULL,
    cve_identifier    TEXT NOT NULL,
    cvss_score        REAL NOT NULL CHECK (cvss_score BETWEEN 0 AND 10),
    severity_level    TEXT NOT NULL CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    affected_asset_id INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    discovery_source  TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'Open'
                      CHECK (status IN ('Open', 'Under Investigation', 'In Progress', 'Resolved', 'Closed')),
    creation_date     TEXT NOT NULL DEFAULT (datetime('now')),
    resolution_date   TEXT
);

-- ---------------------------------------------------------------- Notifications (teammate)
CREATE TABLE IF NOT EXISTS notifications (
    notification_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    title             TEXT NOT NULL,
    message           TEXT NOT NULL,
    notification_type TEXT NOT NULL CHECK (notification_type IN ('Incident Assignment', 'Security Alert',
                                                                 'System Notification', 'Threat Alert',
                                                                 'Vulnerability Alert')),
    severity_level    TEXT NOT NULL CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    status            TEXT NOT NULL DEFAULT 'Unread' CHECK (status IN ('Unread', 'Read')),
    creation_date     TEXT NOT NULL DEFAULT (datetime('now')),
    read_date         TEXT
);

-- ---------------------------------------------------------------- Playbooks (teammate)
CREATE TABLE IF NOT EXISTS playbooks (
    playbook_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_name     TEXT NOT NULL,
    description       TEXT NOT NULL,
    incident_category TEXT NOT NULL,
    severity_level    TEXT NOT NULL CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    created_by        INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    creation_date     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------- Response actions (teammate)
CREATE TABLE IF NOT EXISTS response_actions (
    action_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id        INTEGER NOT NULL REFERENCES playbooks(playbook_id) ON DELETE CASCADE,
    action_description TEXT NOT NULL,
    step_number        INTEGER NOT NULL,
    status             TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'In Progress', 'Completed')),
    assigned_user_id   INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    completion_date    TEXT,
    UNIQUE (playbook_id, step_number)
);
