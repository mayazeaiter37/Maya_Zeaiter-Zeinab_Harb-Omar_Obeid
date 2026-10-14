# Security Incident Detection and Response Management System — Backend

**Services 1–3 (Users and Identity, Asset Management, Incident Management): Maya Zeaiter**

Flask + SQLite REST backend. Every route has a `# Maya Zeaiter` comment, and every JSON response has a `"developer": "Maya Zeaiter"` field.

## Run it

```bash
pip install -r requirements.txt
python seed.py --reset      # creates security_system.db with all 10 tables + sample data
python app.py               # http://127.0.0.1:5050
python -m unittest discover tests -v   # 12 automated API tests
```

Import `postman/Maya_Zeaiter_Services_1-3.postman_collection.json` into Postman. Run the **Authentication** folder first, because it saves the four role tokens into collection variables.

Seeded test accounts (see `seed.py`): `admin_maya`, `analyst_karim`, `analyst_lina`, `user_rami`, `auditor_sara`, `user_suspended`.

## Project layout

| File | Purpose |
|---|---|
| `app.py` | App factory, blueprint registration, global error handlers |
| `schema.sql` | All tables, PKs, FKs, CHECK constraints (shared team DB) |
| `database.py` | SQLite connection (foreign keys ON) and `init_db()` |
| `common.py` | Response format, `ApiError`, token auth, `require_roles` RBAC decorator, audit log writer |
| `validators.py` | Input validation (required fields, email, password, IP, enums, unknown fields) |
| `models.py` | Entity classes (`User`, `Asset`, `Incident`, `InvestigationNote`) and repositories (`BaseRepository` and subclasses) |
| `users_service.py` | Service 1 |
| `assets_service.py` | Service 2 |
| `incidents_service.py` | Service 3 |

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
| 404 | User, asset or incident not found |
| 409 | Duplicate username/email, or a record that is still referenced (e.g. deleting a user who reported incidents) |

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
