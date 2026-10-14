# Security Incident Detection and Response Management System — Backend

**Services 1–3 (Users and Identity, Asset Management, Incident Management): Maya Zeaiter**
**Services 4–6 (Threat Intelligence, Security Audit Logging, Security Reports): Zeinab Harb**

Flask + SQLite REST backend. Every route has a comment with its developer's full name (`# Maya Zeaiter` / `(Zeinab Harb)`), and every JSON response has a `"developer"` field naming the student who built that service.

## Run it

```bash
pip install -r requirements.txt
python seed.py --reset      # creates security_system.db with all 10 tables + sample data
python app.py               # http://127.0.0.1:5050
python -m unittest discover tests -v   # 32 automated API tests (12 Services 1-3, 20 Services 4-6)
```

Import `postman/Maya_Zeaiter_Services_1-3.postman_collection.json` and `postman/Zeinab_Harb_Services_4-6.postman_collection.json` into Postman. In each collection, run the **Authentication** folder first, because it saves the four role tokens into collection variables.

Seeded test accounts (see `seed.py`): `admin_maya`, `analyst_karim`, `analyst_lina`, `user_rami`, `auditor_sara`, `user_suspended`.

## Project layout

| File | Purpose |
|---|---|
| `app.py` | App factory, blueprint registration, global error handlers |
| `schema.sql` | All tables, PKs, FKs, CHECK constraints (shared team DB) |
| `database.py` | SQLite connection (foreign keys ON) and `init_db()` |
| `common.py` | Response format, `ApiError`, token auth, `require_roles` RBAC decorator, audit log writer |
| `validators.py` | Input validation (required fields, email, password, IP, enums, unknown fields) |
| `models.py` | Entity classes (`User`, `Asset`, `Incident`, `InvestigationNote`, `Threat`, `AuditLog`) and repositories (`BaseRepository` and subclasses) |
| `users_service.py` | Service 1 |
| `assets_service.py` | Service 2 |
| `incidents_service.py` | Service 3 |
| `threats_service.py` | Service 4 (Zeinab Harb) |
| `logs_service.py` | Service 5 (Zeinab Harb) |
| `reports_service.py` | Service 6 (Zeinab Harb) |

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
| 404 | User, asset, incident, threat or log not found |
| 405 | Attempt to modify an audit log (logs are append-only) |
| 409 | Duplicate username/email, duplicate threat indicator (same type + value), or a record that is still referenced (e.g. deleting a user who reported incidents) |

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

