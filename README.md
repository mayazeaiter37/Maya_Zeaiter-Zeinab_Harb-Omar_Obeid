# Security Incident Detection and Response Management System — Backend

**Course:** EECE 435L (Software Tools Lab) — Final Project, Sprint 1

**Services 1–3 (Users and Identity, Asset Management, Incident Management): Maya Zeaiter**
**Services 4–6 (Threat Intelligence, Security Audit Logging, Security Reports): Zeinab Harb**
**Services 7–9 (Vulnerability Management, Notification and Alert Management, Security Playbook and Response Automation): Omar Obeid**

Flask + SQLite REST backend. Every route has a comment with its developer's full name (`# Maya Zeaiter` / `(Zeinab Harb)` / `(Omar Obeid)`), and every JSON response has a `"developer"` field naming the student who built that service.

## Run it

```bash
pip install -r requirements.txt
python seed.py --reset      # creates security_system.db with all 10 tables + sample data
python app.py               # http://127.0.0.1:5050
python -m unittest discover tests -v   # 49 automated API tests (12 Services 1-3, 20 Services 4-6, 17 Services 7-9)
```

Import `postman/Maya_Zeaiter_Services_1-3.postman_collection.json`, `postman/Zeinab_Harb_Services_4-6.postman_collection.json` and `postman/Omar_Obeid_Services_7-9.postman_collection.json` into Postman. In each collection, run the **Authentication** folder first, because it saves the four role tokens into collection variables.

Seeded test accounts (see `seed.py`): `admin_maya`, `analyst_karim`, `analyst_lina`, `user_rami`, `auditor_sara`, `user_suspended`.

## Project layout

| File | Purpose |
|---|---|
| `app.py` | App factory, blueprint registration, global error handlers |
| `schema.sql` | All tables, PKs, FKs, CHECK constraints (shared team DB) |
| `database.py` | SQLite connection (foreign keys ON) and `init_db()` |
| `common.py` | Response format, `ApiError`, token auth, `require_roles` RBAC decorator, audit log writer |
| `validators.py` | Input validation (required fields, email, password, IP, enums, unknown fields) |
| `models.py` | Entity classes (`User`, `Asset`, `Incident`, `InvestigationNote`, `Threat`, `AuditLog`, `Vulnerability`, `Notification`, `Playbook`, `ResponseAction`) and repositories (`BaseRepository` and subclasses) |
| `users_service.py` | Service 1 |
| `assets_service.py` | Service 2 |
| `incidents_service.py` | Service 3 |
| `threats_service.py` | Service 4 (Zeinab Harb) |
| `logs_service.py` | Service 5 (Zeinab Harb) |
| `reports_service.py` | Service 6 (Zeinab Harb) |
| `vulnerabilities_service.py` | Service 7 (Omar Obeid) |
| `notifications_service.py` | Service 8 (Omar Obeid) |
| `playbooks_service.py` | Service 9 (Omar Obeid) |

## Response format

```json
{ "status": "success", "message": "...", "developer": "Maya Zeaiter", "data": { } }
{ "status": "error",   "message": "...", "developer": "Maya Zeaiter", "errors": { "field": "reason" } }
```

| Code | Meaning |
|---|---|
| 400 | Validation error, invalid status transition, empty or non-JSON body |
| 401 | Missing, invalid or expired token; wrong username/password |
| 403 | Role not allowed, not the caller's own record, inactive or suspended account |
| 404 | User, asset, incident, threat, log, vulnerability, notification, playbook or action not found |
| 405 | Attempt to modify an audit log (logs are append-only) |
| 409 | Duplicate username/email, duplicate threat indicator (same type + value), duplicate CVE on the same asset, duplicate playbook name or step number, a playbook step started before the earlier steps are completed, or a record that is still referenced (e.g. deleting a user who reported incidents) |

Protected routes need the header `Authorization: Bearer <token>` (the token comes from `POST /users/login`).

---

## Service 1: Users and Identity Management

| API | Method & endpoint | Roles |
|---|---|---|
| User Registration | `POST /users/register` | Public (Regular User only); Admin (any role) |
| User Login | `POST /users/login` | Public |
| Update User | `PUT /users/{id}` | Admin (any user, incl. role/status); Regular User (own name/email/department) |
| Delete User | `DELETE /users/{id}` | Admin |
| Retrieve All Users | `GET /users` | Admin, Auditor |
| Retrieve User By Username | `GET /users/{username}` | Admin, Auditor; Regular User (own) |

**POST /users/register**
```json
{ "full_name": "Nour Moghrabi", "username": "nour_m", "email": "nour@company.com",
  "password": "Secure@2026", "department": "Marketing", "role": "Regular User" }
```
Validation: all fields required; username is 3–30 characters from `[A-Za-z0-9_.]` and must be unique; email must be valid and unique; password needs at least 8 characters with an uppercase letter, a lowercase letter, a digit and a symbol; role must be one of `Security Administrator`, `Security Analyst`, `Regular User`, `Auditor`. The admin may also send `account_status` (`Active`/`Inactive`/`Suspended`).
→ `201` with the user (without the password hash) · `400` · `403` (privileged role without an admin token) · `409` (duplicate).

**POST /users/login**
```json
{ "username": "admin_maya", "password": "Admin@1234" }
```
`username` also accepts the email address. → `200` with `{ token, token_type, expires_in_seconds, user }` · `401` · `403` (inactive or suspended account).

**PUT /users/{id}**: `{ "full_name": "...", "email": "...", "department": "..." }`. The admin can also send `role` and `account_status`. → `200 { before, after }` · `400` · `403` · `404` · `409`.

**DELETE /users/{id}** → `200` · `400` (deleting yourself) · `403` · `404` · `409` (the user still owns assets or reported incidents).

**GET /users** → `200 { count, users: [...] }`. **GET /users/{username}** → `200` user · `404`.

## Service 2: Asset Management

| API | Method & endpoint | Roles |
|---|---|---|
| Add New Asset | `POST /assets` | Admin |
| Update Asset | `PUT /assets/{id}` | Admin |
| Delete Asset | `DELETE /assets/{id}` | Admin |
| Retrieve All Assets | `GET /assets` | Admin, Auditor |
| Retrieve Specific Asset | `GET /assets/{id}` | Admin, Analyst, Auditor |
| Search Assets | `GET /assets/search` | Admin, Analyst, Auditor |

**POST /assets**
```json
{ "asset_name": "Mail Server", "asset_type": "Server", "ip_address": "10.0.0.25",
  "operating_system": "Ubuntu 24.04", "department": "IT Security", "owner_id": 1,
  "location": "Data Center B", "criticality_level": "High", "status": "Active" }
```
Required: `asset_name, asset_type, ip_address, department, owner_id, criticality_level`.
`asset_type` ∈ Server, Workstation, Database, Application, Network Device, Cloud Resource · `criticality_level` ∈ Low, Medium, High, Critical · `status` ∈ Active, Inactive, Under Maintenance (default Active) · `ip_address` must be a valid IPv4 or IPv6 address · `owner_id` must be an existing user.
→ `201` · `400` · `403` · `404` (owner not found).

**PUT /assets/{id}** takes any subset of the fields above → `200 { before, after }`.
**GET /assets/{id}** returns the asset plus `owner` and `related_incidents`.
**GET /assets/search** query params: `name`, `ip`, `department` (partial, case-insensitive), `type`, `criticality`, `status` (exact). Several params are combined with AND, e.g. `/assets/search?name=server&criticality=Critical`.

## Service 3: Incident Management

| API | Method & endpoint | Roles |
|---|---|---|
| Create Incident | `POST /incidents` | Admin, Regular User |
| Retrieve All Incidents | `GET /incidents` | Admin, Auditor |
| Retrieve Specific Incident | `GET /incidents/{id}` | Admin, Auditor; Analyst (assigned); Regular User (reported) |
| Assign Incident | `PUT /incidents/{id}/assign` | Admin |
| Update Incident Status | `PUT /incidents/{id}/status` | Admin; Analyst (assigned, not Closed) |
| Add Investigation Notes | `POST /incidents/{id}/notes` | Admin; Analyst (assigned) |

**POST /incidents**
```json
{ "title": "Data exfiltration from customer DB", "description": "...",
  "category": "Data Leakage", "severity": "Critical", "asset_id": 3 }
```
`category` ∈ Malware Infection, Unauthorized Access, Phishing Attack, Data Leakage, Account Compromise, Denial of Service, Other · `severity` ∈ Low, Medium, High, Critical. The reporter is the logged-in user; an admin may pass `reporter_id`.

**PUT /incidents/{id}/assign**: `{ "analyst_id": 2 }`. Checks that the incident exists and is not Closed, and that the user exists, is a Security Analyst and is Active. It writes an audit log and a notification.

**PUT /incidents/{id}/status**: `{ "status": "Under Investigation" }`. Only the next step is allowed:
`Open → Under Investigation → Mitigated → Resolved → Closed`. Starting the investigation requires an assigned analyst, only an admin can close an incident, and `Resolved` sets `resolution_date`.

**POST /incidents/{id}/notes**: `{ "note_content": "..." }` → `201 { note, incident }` (the incident includes all its notes).

---

## Service 4: Threat Intelligence (Zeinab Harb)

| API | Method & endpoint | Roles |
|---|---|---|
| Add Threat Indicator | `POST /threats` | Admin |
| Retrieve All Threat Indicators | `GET /threats` | Admin, Analyst, Auditor |
| Retrieve Specific Threat Indicator | `GET /threats/{id}` | Admin, Analyst, Auditor |
| Search Threat Indicators | `GET /threats/search` | Admin, Analyst, Auditor |
| Update Threat Information | `PUT /threats/{id}` | Admin |
| Delete Threat Indicator | `DELETE /threats/{id}` | Admin |

Regular Users get `403` on every threat route. The spec's service table leaves Auditor search out, but the Auditor role description lists "Search threat indicators", so Auditors may search.

**POST /threats**
```json
{ "threat_type": "IP Address", "threat_value": "192.0.2.10",
  "description": "Source of repeated RDP brute-force attempts", "severity_level": "High", "source": "Firewall logs" }
```
All five fields are required. `threat_type` ∈ IP Address, Domain, File Hash, Malware Signature, Other · `severity_level` ∈ Low, Medium, High, Critical. `threat_value` is validated by type:

- **IP Address:** valid IPv4/IPv6, stored in canonical form.
- **Domain:** labels of letters, digits and hyphens plus a TLD, stored lowercase.
- **File Hash:** hexadecimal MD5 (32), SHA-1 (40), SHA-256 (64) or SHA-512 (128), stored lowercase.
- **Malware Signature / Other:** free text up to 255 characters.

→ `201` threat · `400` · `403` · `409` (same type + value already exists).

**GET /threats** → `200 { count, threats: [ {threat_id, threat_type, threat_value, description, severity_level, source, date_added} ] }`.
**GET /threats/{id}** → `200` threat · `404`.

**GET /threats/search** query params: `type`, `severity` (exact, validated) and `value`, `source` (partial, case-insensitive). Parameters combine with AND, e.g. `/threats/search?type=Domain&severity=High`. At least one is required; unknown parameters → `400`.

**PUT /threats/{id}**: `{ "description": "...", "severity_level": "Critical", "source": "..." }`, any subset. `threat_type` and `threat_value` are read-only (`400`). → `200 { before, after }` · `400` · `403` · `404`.

**DELETE /threats/{id}** → `200 { deleted_threat_id, deleted_threat }` · `403` · `404`.

Creates, updates and deletes write `THREAT_CREATED` / `THREAT_UPDATED` / `THREAT_DELETED` audit logs.

## Service 5: Security Audit Logging (Zeinab Harb)

| API | Method & endpoint | Roles |
|---|---|---|
| Create Log Record | `POST /logs` | Admin |
| Retrieve All Logs | `GET /logs` | Admin, Auditor |
| Retrieve Specific Log | `GET /logs/{id}` | Admin, Auditor, Analyst |
| Search Logs | `GET /logs/search` | Admin, Auditor, Analyst |
| Delete Logs | `DELETE /logs/{id}` | Admin |
| Retrieve Logs By User | `GET /logs/user/{user_id}` | Admin, Auditor |

Logs are generated automatically by every service through `common.write_log()`:

- `LOGIN_SUCCESS`, `LOGIN_FAILED`
- `USER_CREATED`, `USER_DELETED`, `ROLE_CHANGED`
- `UNAUTHORIZED_ACCESS`
- `ASSET_*`, `INCIDENT_*`, `THREAT_*`, `LOG_DELETED`

**POST /logs** adds manual records:
```json
{ "user_id": 2, "action_performed": "MALWARE_SCAN_COMPLETED", "description": "Weekly scan finished",
  "severity_level": "Information", "related_service": "Asset Management" }
```
- `user_id` must be an existing user.
- `action_performed` is normalised to UPPER_SNAKE_CASE (3–50 characters).
- `severity_level` ∈ Information, Warning, Error, Critical.
- `related_service` must be one of the nine service names.

→ `201` · `400` · `403` · `404`.

**GET /logs** → `200 { count, logs: [...] }`, newest first. Each log includes `username`.
**GET /logs/{id}** → `200` · `404`.

**GET /logs/search** query params:

- `user`: a user id or a username.
- `date`: `YYYY-MM-DD`, compared with the UTC date of `timestamp`.
- `action`, `service`: partial, case-insensitive.
- `severity`: exact.

Parameters combine with AND.

**GET /logs/user/{user_id}** → `200 { user, count, logs }`. `count` is 0 with an empty list when the user has no activity, and the response is `404` when the user does not exist.

**DELETE /logs/{id}** → `200` · `403` · `404`. Every deletion writes a new `LOG_DELETED` record.

**Audit log protection:** there is no update. `PUT`/`PATCH /logs/{id}` return `405` and log the attempt as `LOG_MODIFICATION_BLOCKED`.

Timestamps are stored in UTC (SQLite `datetime('now')`).

## Service 6: Security Reports (Zeinab Harb)

All report routes: **Admin and Auditor only** (Analyst and Regular User → `403`). Each report returns `report`, `generated_at`, `generated_by` and the statistics below. Grouped counts list every allowed value, including zeros.

| API | Endpoint | Contents (data source) |
|---|---|---|
| Security Summary | `GET /reports/summary` | users, active_users, assets, critical_assets, incidents, open_incidents, critical_open_incidents, threats, critical_threats, vulnerabilities, open_vulnerabilities, audit_log_records, failed_logins, unauthorized_access_attempts, recent_security_activities (all tables) |
| Incident Report | `GET /reports/incidents` | total, open, unassigned, by severity, by status, by category, recent (incidents) |
| Asset Report | `GET /reports/assets` | total, critical count and list, by type, by criticality, by status (assets) |
| Threat Report | `GET /reports/threats` | total, by severity, by type, recently added (threats) |
| Vulnerability Report | `GET /reports/vulnerabilities` | total, by severity, by status, critical count and list, average CVSS (vulnerabilities joined with assets) |
| Activity Report | `GET /reports/activity` | total activities, login attempts, successful/failed logins, unauthorized attempts, most performed actions, most active users, by severity, by service (logs joined with users) |

"Open" incidents and vulnerabilities are those whose status is not Resolved or Closed.

---

## Service 7: Vulnerability Management (Omar Obeid)

| API | Method & endpoint | Roles |
|---|---|---|
| Create Vulnerability Record | `POST /vulnerabilities` | Admin |
| Retrieve All Vulnerabilities | `GET /vulnerabilities` | Admin, Analyst, Auditor |
| Retrieve Specific Vulnerability | `GET /vulnerabilities/{id}` | Admin, Analyst, Auditor |
| Update Vulnerability Status | `PUT /vulnerabilities/{id}` | Admin, Analyst |
| Search Vulnerabilities | `GET /vulnerabilities/search` | Admin, Analyst, Auditor |
| Delete Vulnerability | `DELETE /vulnerabilities/{id}` | Admin |

Regular Users get `403` on every vulnerability route.

**POST /vulnerabilities**
```json
{ "title": "Apache HTTP Server path traversal", "description": "Path traversal and RCE in Apache 2.4.49",
  "cve_identifier": "CVE-2021-41773", "cvss_score": 7.5, "severity_level": "High",
  "affected_asset_id": 1, "discovery_source": "Nessus scan" }
```
All seven fields are required. The rules are:

- `cve_identifier` must match `CVE-YYYY-NNNN` (4 or more digits, year 1999 to next year). It is stored upper-case.
- `cvss_score` is a number from 0.0 to 10.0 with one decimal place.
- `severity_level` must agree with the CVSS v3 rating: 0–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10.0 Critical.
- `affected_asset_id` must be an existing asset.
- The same CVE cannot be recorded twice on the same asset.

New records start as `Open`. A High or Critical vulnerability also sends a **Vulnerability Alert** notification to the asset owner.
→ `201` (record with an `affected_asset` summary) · `400` · `403` · `404` (asset not found) · `409` (duplicate CVE on that asset).

**GET /vulnerabilities** → `200 { count, vulnerabilities: [...] }`. **GET /vulnerabilities/{id}** → `200` · `404`.

**PUT /vulnerabilities/{id}** takes any subset of `description`, `severity_level`, `status`, `cvss_score` and `resolution_date`:
```json
{ "status": "Under Investigation" }
{ "cvss_score": 6.5, "severity_level": "Medium", "description": "RCE blocked; path traversal remains" }
```
- Status moves one step at a time: `Open → Under Investigation → In Progress → Resolved → Closed`.
- Severity and CVSS must still agree after the update.
- Moving to `Resolved` sets `resolution_date` automatically. A `resolution_date` (`YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`, not in the future, not before creation) may only be sent when the record is Resolved or Closed.
- `title`, `cve_identifier`, `affected_asset_id` and `discovery_source` are read-only (`400`).

→ `200 { before, after }` · `400` · `403` · `404`.

**GET /vulnerabilities/search** query params: `cve` (partial, case-insensitive), `severity`, `status` (exact, validated) and `asset` (asset id). Parameters combine with AND, e.g. `/vulnerabilities/search?severity=High&status=Open&asset=1`. At least one is required; unknown parameters → `400`.

**DELETE /vulnerabilities/{id}** → `200 { deleted_vulnerability_id, deleted_vulnerability }` · `403` · `404`.

Creates, updates and deletes write `VULNERABILITY_CREATED` / `VULNERABILITY_UPDATED` / `VULNERABILITY_STATUS_CHANGED` / `VULNERABILITY_DELETED` audit logs. Zeinab's `GET /reports/vulnerabilities` reads the same table.

## Service 8: Notification and Alert Management (Omar Obeid)

| API | Method & endpoint | Roles |
|---|---|---|
| Create Notification | `POST /notifications` | Admin, Analyst |
| Retrieve User Notifications | `GET /notifications/user/{user_id}` | Admin, Auditor (any user); Analyst, Regular User (own) |
| Retrieve Specific Notification | `GET /notifications/{id}` | Admin, Auditor (any); Analyst, Regular User (own) |
| Mark Notification as Read | `PUT /notifications/{id}/read` | Recipient; Admin |
| Search Notifications | `GET /notifications/search` | Admin, Auditor (all); Analyst, Regular User (own inbox only) |
| Delete Notification | `DELETE /notifications/{id}` | Admin |

**POST /notifications**
```json
{ "user_id": 4, "title": "Suspicious login to your account", "message": "New login from 203.0.113.45",
  "notification_type": "Security Alert", "severity_level": "High" }
```
`notification_type` ∈ Incident Assignment, Security Alert, System Notification, Threat Alert, Vulnerability Alert · `severity_level` ∈ Low, Medium, High, Critical · `user_id` must be an existing, Active user. New notifications are `Unread` with no `read_date`.
→ `201` · `400` · `403` · `404` (recipient not found).

Notifications are also created automatically by other services:

- Incident assigned (Service 3) → Incident Assignment.
- High or Critical vulnerability recorded (Service 7) → Vulnerability Alert to the asset owner.
- Response action assigned (Service 9) → System Notification.

**GET /notifications/user/{user_id}** → `200 { user, count, unread_count, notifications }`, newest first. A user with no notifications returns `count: 0` and an empty list. An unknown user → `404`; another user's inbox (not Admin/Auditor) → `403`.

**GET /notifications/{id}** → `200` · `403` (not yours) · `404`.

**PUT /notifications/{id}/read** (no body) sets `status = "Read"` and `read_date` to the current UTC time. Calling it again returns `200` and keeps the first `read_date`. → `200` · `403` · `404`.

**GET /notifications/search** query params: `user` (id or username), `type`, `severity`, `status` (exact, validated). They combine with AND, e.g. `/notifications/search?user=4&status=Unread`. Analysts and Regular Users only search their own notifications; asking for another user → `403`.

**DELETE /notifications/{id}** → `200` · `403` · `404`.

## Service 9: Security Playbook and Response Automation (Omar Obeid)

| API | Method & endpoint | Roles |
|---|---|---|
| Create Playbook | `POST /playbooks` | Admin |
| Retrieve All Playbooks | `GET /playbooks` | Admin, Analyst, Auditor |
| Retrieve Specific Playbook | `GET /playbooks/{id}` | Admin, Analyst, Auditor |
| Add Response Action | `POST /playbooks/{id}/actions` | Admin, Analyst |
| Update Response Action Status | `PUT /actions/{id}/status` | Admin; Analyst (own or unassigned actions) |
| Delete Playbook | `DELETE /playbooks/{id}` | Admin |

**POST /playbooks**
```json
{ "playbook_name": "DDoS Mitigation", "description": "Keep public services online during a traffic flood",
  "incident_category": "Denial of Service", "severity_level": "High" }
```
`incident_category` uses the incident categories of Service 3 · `severity_level` ∈ Low, Medium, High, Critical · names are unique (case-insensitive). `created_by` is the logged-in administrator.
→ `201` · `400` · `403` · `409` (duplicate name).

**GET /playbooks** → `200 { count, playbooks: [...] }`, each with `progress { total_steps, completed_steps, percent_complete }`.
**GET /playbooks/{id}** → `200` playbook with its `actions` ordered by `step_number`, plus `progress` · `404`.

**POST /playbooks/{id}/actions**
```json
{ "action_description": "Contact the ISP to enable upstream scrubbing", "step_number": 2, "assigned_user_id": 3 }
```
`step_number` is a positive integer, unique within the playbook (`409` otherwise). Steps may be added in any order. `assigned_user_id` is optional and must be an Active Administrator or Analyst, who is then notified. New actions are `Pending`.
→ `201 { action, playbook }` · `400` · `403` · `404` · `409`.

**PUT /actions/{id}/status**
```json
{ "status": "In Progress", "assigned_user_id": 2 }
{ "status": "Completed", "completion_date": "2026-10-20" }
```
- Status moves one step at a time: `Pending → In Progress → Completed`.
- A step can only start once every earlier step of the playbook is Completed (`409`).
- An unassigned step is assigned to whoever starts it. Analysts can only update their own or unassigned steps, and can only assign themselves.
- `Completed` sets `completion_date` (now, or the given date, which cannot be in the future).

→ `200 { before, after, playbook_progress }` · `400` · `403` · `404` · `409`.

**DELETE /playbooks/{id}** → `200 { deleted_playbook_id, deleted_actions, deleted_playbook }`. Its response actions are removed by `ON DELETE CASCADE`. → `403` · `404`.

Playbook and action changes write `PLAYBOOK_CREATED`, `PLAYBOOK_DELETED`, `RESPONSE_ACTION_ADDED` and `RESPONSE_ACTION_STATUS_CHANGED` audit logs. Notification changes write `NOTIFICATION_CREATED`, `NOTIFICATION_READ` and `NOTIFICATION_DELETED`. Permission violations in all three services are logged as `UNAUTHORIZED_ACCESS`.
