# Report Sections: Maya Zeaiter (Services 1–3)

Draft text to paste into the common team report. Put "(Maya Zeaiter)" next to each heading. Rewrite it in your own words where you want, and **take every screenshot yourself from your running system**.

---

## 5. Implementation Details (Maya Zeaiter)

### Architecture of my services
The backend is a Flask application. Each service is a Flask **Blueprint** (`users_service.py`, `assets_service.py`, `incidents_service.py`) registered in `app.py`. The services share:
- **Entity classes** (`User`, `Asset`, `Incident`, `InvestigationNote`), which are Python dataclasses. Each has a `to_dict()` method; `User.to_dict()` hides the password hash. `Incident` encapsulates the lifecycle rules in `next_status()` and `can_transition_to()`.
- **Repositories** (`BaseRepository`, with subclasses `UserRepository`, `AssetRepository`, `IncidentRepository` and `NoteRepository`). They demonstrate inheritance: the base class implements generic `get_by_id`, `get_all`, `insert`, `update`, `delete` and `search`, and each subclass only sets its table and primary key and adds specific queries such as `get_by_username_or_email` or `for_incident`.
- **`common.py`**, which holds the response format, the `ApiError` exception, token handling, the `require_roles` decorator and `write_log()`. `write_log()` inserts into the shared `logs` table used by the Security Audit Logging Service.

### Service 1: Users and Identity Management (Maya Zeaiter)
**Responsibility:** manages accounts, authentication, roles and account status.

**How duplicate usernames are handled.** The database declares `username` and `email` as `UNIQUE`. Before inserting, the API also checks (case-insensitively) whether the username or email already exists. If it does, it returns `409 Conflict` with the message `Username 'x' is already taken`, so no second row is ever created.

**Authentication mechanism.**
1. At registration, the password is hashed with Werkzeug's `generate_password_hash` (PBKDF2-SHA256 with a random salt). Only the hash is stored in `users.password_hash`, never the plain-text password.
2. At login, the user is looked up by username *or* email, and `check_password_hash` compares the submitted password with the stored hash.
3. If the account is not `Active`, login is refused with `403`, which blocks inactive and suspended users.
4. On success, the server returns a **signed token** (itsdangerous `URLSafeTimedSerializer`, signed with the app's `SECRET_KEY`). The token contains the user id and role and expires after 8 hours.
5. Every protected request sends `Authorization: Bearer <token>`. The server verifies the signature and expiry, then reloads the user from the database, so a deleted or suspended user loses access immediately.
6. Every successful and failed login is written to the audit log (`LOGIN_SUCCESS` / `LOGIN_FAILED`).

**How permissions are checked (e.g. for Delete User).** Each route is decorated with `@require_roles(...)`, which lists the roles allowed to call it (`DELETE /users/{id}` allows only `Security Administrator`). The decorator does three things:
1. It authenticates the token (`401` if the token is missing or invalid).
2. It compares the user's role with the allowed list. If the role is not allowed, it writes an `UNAUTHORIZED_ACCESS` log with severity *Warning* and returns `403`.
3. Only if both checks pass does it run the route.

Record-level rules are enforced inside the route. For example, a Regular User may only update or view *their own* account, and these violations are logged the same way.

**Data structure returned by GET /users.** The response is `{status, message, developer, data: {count, users: [...]}}`. Each user has `user_id, full_name, username, email, department, role, account_status, created_date, last_login_date`. The password hash is never returned.

**GET /users/{username} responses.** An existing user returns `200` with the user object. A non-existing user returns `404` with `{"status":"error","message":"User 'ghost_user' not found"}`.

### Service 2: Asset Management (Maya Zeaiter)
**Responsibility:** manages organizational assets (servers, workstations, databases, applications, network devices and cloud resources).

**How asset criticality is stored.** `criticality_level` is a `TEXT` column with a `CHECK (criticality_level IN ('Low','Medium','High','Critical'))` constraint. The API validates the value first and returns a clear `400`; the CHECK constraint is a second safety net at the database level. Asset type and status are stored the same way.

**Authorization for delete.** Only `Security Administrator` is listed in `@require_roles` for `DELETE /assets/{id}`. An analyst or auditor gets `403`, and the attempt is recorded in the logs. Deleting an asset sets `incidents.asset_id` to NULL, so incident history is kept.

**Response format of GET /assets.** `data: {count, assets: [...]}`. Each asset includes its details, `criticality_level` and current `status`. `GET /assets/{id}` additionally returns the `owner` and the `related_incidents` (the Users→Assets and Assets→Incidents relationships).

**How search works.** Query parameters are mapped to a whitelist of columns. `name`, `ip` and `department` use a case-insensitive partial match (`LIKE %value%`). `type`, `criticality` and `status` must match exactly and are validated against the allowed values. When several parameters are given, they are combined with `AND`. Values are passed as SQL parameters (`?`), never concatenated into the query, so the injection attempt `name=' OR '1'='1` returns 0 results.

### Service 3: Incident Management (Maya Zeaiter)
**Responsibility:** manages the full incident lifecycle, assignment to analysts and investigation notes.

**Why each severity level was selected** (adapt this to the incidents you create):
- *Critical*: data exfiltration from the customer database, which stores sensitive data and requires immediate response.
- *High*: repeated suspicious logins on the customer database, which affect an important system.
- *Medium*: a phishing email to a single employee, which needs investigation but has no confirmed compromise.
- *Low*: browser pop-ups on one workstation, a minor event with limited impact.

**Implemented workflow.** `Incident.STATUS_FLOW = [Open, Under Investigation, Mitigated, Resolved, Closed]`. An incident may only move to the *next* status in the list. Skipping a step (e.g. Open → Closed) or going backwards returns `400` with the allowed flow. Additional rules:
- the incident must be assigned to an analyst before it can become *Under Investigation*;
- only the assigned analyst (or an admin) can change the status;
- only an admin can close an incident;
- reaching *Resolved* sets `resolution_date`;
- every transition is written to the audit log.

**Assignment validation.** The API checks that the incident exists and is not Closed, and that the target user exists, has the *Security Analyst* role and is Active. The assignment is logged (`INCIDENT_ASSIGNED`), and an *Incident Assignment* notification is created for the analyst.

**How notes are associated with incidents.** `investigation_notes.incident_id` is a foreign key to `incidents.incident_id` (`ON DELETE CASCADE`), and `analyst_id` is a foreign key to `users`. This gives one incident → many notes, with each note belonging to exactly one incident. `GET /incidents/{id}` loads the notes through `NoteRepository.for_incident()` and returns them inside the incident.

---

## 6. Database Design: my tables (Maya Zeaiter)

| Table | PK | Foreign keys | Notes |
|---|---|---|---|
| `users` | `user_id` | — | `username`, `email` UNIQUE; CHECK on `role`, `account_status` |
| `assets` | `asset_id` | `owner_id → users` (RESTRICT) | CHECK on type, criticality, status |
| `incidents` | `incident_id` | `reporter_id → users`, `asset_id → assets` (SET NULL), `assigned_analyst_id → users` (SET NULL) | CHECK on severity, status |
| `investigation_notes` | `note_id` | `incident_id → incidents` (CASCADE), `analyst_id → users` | |

**Design decisions:**
- Enumerations are stored as readable text with `CHECK` constraints, so the database rejects invalid values even if the API is bypassed.
- `PRAGMA foreign_keys = ON` is set on every connection.
- Deletes are designed to protect history. A user who owns assets or reported incidents cannot be deleted (`409`), and should be set to *Inactive* instead. Deleting an asset keeps its incidents but unlinks them.
- `schema.sql` also creates the tables for my teammates' services (threats, logs, vulnerabilities, notifications, playbooks and response_actions), so the team shares one database.

---

## 7. Error Handling and Validation (Maya Zeaiter)
- Any route can raise `ApiError(message, status_code, errors)`. A single handler in `app.py` converts it into `{"status":"error","message":...,"errors":{field: reason}}`. 404, 405, database-constraint errors (`409`) and unexpected exceptions (`500`, with no stack trace leaked) are handled the same way, so the error format is consistent.
- Validation covers:
  - empty or non-JSON bodies;
  - missing required fields;
  - unexpected or extra fields (e.g. a Regular User sending `role`);
  - wrong types;
  - string length limits;
  - email, username and password rules;
  - IPv4/IPv6 format;
  - all enumerations;
  - positive integer IDs;
  - existence of referenced users and assets;
  - the incident status workflow.
- Every SQL query uses parameter placeholders. Only whitelisted column names are ever put into the query text, which protects against SQL injection.

---

## Screenshot checklist (take these yourself in Postman, in collection order)

Caption format required by the spec: **"Maya Zeaiter – <API title> – <what it does>"**

1. Maya Zeaiter – User Registration – creates a Regular User (201) + DB Browser showing the new row with a hashed password
2. Maya Zeaiter – User Registration – duplicate username rejected (409)
3. Maya Zeaiter – User Registration – invalid email/weak password rejected (400)
4. Maya Zeaiter – User Login – successful login returns token
5. Maya Zeaiter – User Login – wrong password rejected (401)
6. Maya Zeaiter – Update User – before/after + DB row
7. Maya Zeaiter – Delete User – successful (200) and auditor attempt denied (403)
8. Maya Zeaiter – Retrieve All Users
9. Maya Zeaiter – Retrieve User By Username – existing (200) and non-existing (404)
10. Maya Zeaiter – Add Asset – three assets created + DB rows
11. Maya Zeaiter – Update Asset – before/after + DB
12. Maya Zeaiter – Delete Asset – admin success / analyst denied
13. Maya Zeaiter – Retrieve All Assets
14. Maya Zeaiter – Retrieve Specific Asset – existing / invalid id
15. Maya Zeaiter – Search Assets – criticality, type, IP, name+department, invalid, SQL injection
16. Maya Zeaiter – Create Incident – Critical / Medium / Low + DB rows
17. Maya Zeaiter – Retrieve All Incidents
18. Maya Zeaiter – Retrieve Specific Incident – existing / invalid
19. Maya Zeaiter – Assign Incident – success, non-analyst rejected, analyst attempt denied
20. Maya Zeaiter – Update Incident Status – each of the 4 transitions + invalid skip (Open → Closed)
21. Maya Zeaiter – Add Investigation Notes – note added, incident retrieved with notes
22. Maya Zeaiter – Authorization – same API with insufficient vs correct role (e.g. GET /users as analyst vs admin)
23. DB Browser for SQLite: table structure of users/assets/incidents/investigation_notes, plus the `logs` table showing LOGIN_FAILED / UNAUTHORIZED_ACCESS rows

## 11. References / AI usage (Maya Zeaiter)
- Flask documentation (flask.palletsprojects.com), Werkzeug security helpers, itsdangerous, SQLite docs.
- AI usage: *(state honestly how you used Claude, e.g. "used Claude (Anthropic) to help scaffold the Flask services, validation helpers and the Postman collection; I reviewed, ran and tested all code myself")*.
