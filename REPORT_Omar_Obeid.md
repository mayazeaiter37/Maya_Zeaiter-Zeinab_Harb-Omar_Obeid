# Report Sections: Omar Obeid (Services 7–9)

EECE 435L Final Project, Sprint 1. This is draft text to paste into the common team report. Put "(Omar Obeid)" next to each heading. Rewrite it in your own words where you want, and **take every screenshot yourself from your running system** (`python seed.py --reset`, `python app.py`, then run `postman/Omar_Obeid_Services_7-9.postman_collection.json` in order).

---

## 5. Implementation Details (Omar Obeid)

### Architecture of my services

My three services follow the same structure as Services 1–6. Each one is a Flask **Blueprint** (`vulnerabilities_service.py`, `notifications_service.py`, `playbooks_service.py`) registered in `app.py`, and they reuse the team's shared code:

- **Entity classes** `Vulnerability`, `Notification`, `Playbook` and `ResponseAction` (dataclasses in `models.py`). Each holds its allowed values (e.g. `Vulnerability.STATUS_FLOW`, `Notification.TYPES`) and a `to_dict()` method. The two entities with a lifecycle (`Vulnerability`, `ResponseAction`) have `next_status()` and `can_transition_to()`, the same design Maya used for `Incident`. `Vulnerability.severity_for_score()` encodes the CVSS v3 rating scale. `Playbook.progress()` computes how many steps are completed.
- **Repositories** `VulnerabilityRepository`, `NotificationRepository`, `PlaybookRepository` and `ActionRepository` inherit from Maya's `BaseRepository`. They reuse `get_by_id`, `get_all`, `insert`, `update`, `delete` and `search`, and add their own queries:
  - `VulnerabilityRepository.find_duplicate()`: same CVE on the same asset.
  - `NotificationRepository.for_user()`, `filter()` and `mark_read()`. `get_all()` is overridden to return newest first.
  - `ActionRepository.for_playbook()` returns steps ordered by `step_number`; `step_taken()` and `unfinished_before()` enforce step rules.
  - `PlaybookRepository` **overrides** `get_by_id()` and `get_all()` to attach each playbook's ordered actions (composition: a playbook *has* actions).
- **Shared helpers** in `common.py`:
  - `require_roles(..., service=SERVICE)` checks the token and role and logs violations under my service names.
  - `deny()` handles record-level rules ("only your own notifications").
  - `write_log()` records audit events.
  - `success()`/`error_body()` build the response format.
- **Developer name.** I call Zeinab's `set_developer(blueprint, "Omar Obeid")` on my three blueprints, so every response from my routes, including 401/403 errors, shows `"developer": "Omar Obeid"`. Every route also has a `(Omar Obeid)` comment.
- **Validators** added to `validators.py`: `check_cve()`, `check_cvss()` and `parse_datetime()`.

**Communication between services.** All services run in one Flask application and share one SQLite database.
- My Notification Service exposes `send_notification()`, which the Vulnerability and Playbook services call. Maya's Incident Service already inserts "Incident Assignment" notifications into the same table.
- My services send every change and every permission violation to Zeinab's Audit Logging Service through `write_log()`.
- Zeinab's `GET /reports/vulnerabilities` and summary report read my `vulnerabilities` table, so I kept its columns exactly as defined in `schema.sql`.
- Playbooks reuse the incident categories defined by the Incident Management Service, so a playbook always matches a real incident category.

### Service 7: Vulnerability Management (Omar Obeid)

**Responsibility:** tracks known weaknesses (CVEs) found on the organisation's assets, from discovery until they are closed.

**APIs:** `POST /vulnerabilities`, `GET /vulnerabilities`, `GET /vulnerabilities/{id}`, `PUT /vulnerabilities/{id}`, `GET /vulnerabilities/search`, `DELETE /vulnerabilities/{id}` (request and response formats are in the README).

**Database interaction:** the `vulnerabilities` table, with `affected_asset_id` as a foreign key to `assets`. It uses `INSERT` on create, parameterised `SELECT` on read and search, `UPDATE` of the five updatable fields, and `DELETE`.

**How a vulnerability record is validated on creation.**
1. The body must be non-empty JSON with exactly the seven fields; missing or unknown fields give `400`.
2. **CVE format:** `^CVE-(\d{4})-(\d{4,})$`, the official CVE ID syntax (four or more digits after the year). The year must be between 1999, when the CVE list started, and next year. Input is upper-cased before checking and storing, so `cve-2023-48795` is accepted and stored as `CVE-2023-48795`.
3. **CVSS score:** a number (not a string or boolean) between 0.0 and 10.0 with one decimal place, as CVSS scores are published.
4. **Severity:** must be Low, Medium, High or Critical **and agree with the CVSS score** using the CVSS v3 qualitative scale. A score of 9.8 labelled "Low" is rejected with the expected rating in the message. This prevents a critical vulnerability from being hidden in reports by a wrong label.

   | CVSS score | Severity |
   |---|---|
   | 0.0–3.9 | Low |
   | 4.0–6.9 | Medium |
   | 7.0–8.9 | High |
   | 9.0–10.0 | Critical |

5. **Affected asset:** must exist in the `assets` table (`404` otherwise).
6. **Duplicates:** the same CVE on the same asset returns `409` with the existing id. The same CVE on *different* assets is allowed, because each affected asset needs its own remediation.

New records start as `Open`. When the severity is High or Critical, the asset's owner automatically receives a **Vulnerability Alert** notification.

**Vulnerability records created for evidence (Postman):**

| CVE | Asset | CVSS | Severity | Why |
|---|---|---|---|---|
| CVE-2021-41773 | 1 Main Web Server | 7.5 | High | Apache path traversal, exploitable remotely without authentication. |
| CVE-2022-22965 | 3 Customer Database | 9.8 | Critical | Spring4Shell remote code execution on a critical asset. |
| CVE-2023-48795 | 2 Finance Workstation | 5.9 | Medium | Terrapin SSH attack needs a man-in-the-middle position, so its impact is lower. |

The seed data adds six more (Log4Shell, regreSSHion, etc.) covering every status.

**GET /vulnerabilities and GET /vulnerabilities/{id}.** The response is `{status, message, developer, data: {count, vulnerabilities: [...]}}`. Each record includes an `affected_asset` summary (name, IP, criticality) taken from the Asset Management table, so the reader does not need a second request. An unknown id gives `404 "Vulnerability with id 99999 not found"`.

**How status transitions are enforced (PUT /vulnerabilities/{id}).**
- The lifecycle is `Open → Under Investigation → In Progress → Resolved → Closed`. A status change must be exactly the next step (`can_transition_to()`). Skipping (Open → Resolved) or going back (Closed → Open) returns `400` with the allowed flow and the next permitted status.
- Moving to **Resolved** sets `resolution_date` automatically. An explicit `resolution_date` is only accepted when the record is Resolved or Closed, cannot be in the future and cannot be before `creation_date`.
- If `cvss_score` or `severity_level` changes, the pair must still agree after the update (e.g. lowering 7.5 to 6.5 requires Medium).
- `title`, `cve_identifier`, `affected_asset_id` and `discovery_source` are read-only (`400`). Changing them would describe a different finding, so the record should be deleted and recreated.
- The response contains `before` and `after`. The audit log records each changed field (e.g. `status: 'Open' -> 'Under Investigation'`) as `VULNERABILITY_STATUS_CHANGED` or `VULNERABILITY_UPDATED`.

**How search results are generated (GET /vulnerabilities/search).**
1. Parameters map to a whitelist of columns:
   - `cve` → `cve_identifier` (partial, case-insensitive `LIKE`);
   - `severity` → `severity_level` and `status` → `status` (exact, validated);
   - `asset` → `affected_asset_id` (positive integer).
2. Each parameter becomes one `WHERE` condition joined with `AND`, through `BaseRepository.search()`.
3. All values are bound parameters, so `cve=' OR '1'='1` returns 0 rows.
4. No parameters, unknown parameters or invalid values return `400`.

**Deletion.** Only the Security Administrator can delete (`@require_roles(ADMIN)`). Analysts get `403` and an `UNAUTHORIZED_ACCESS` log. A successful deletion returns the deleted record and writes `VULNERABILITY_DELETED` (Warning).

### Service 8: Notification and Alert Management (Omar Obeid)

**Responsibility:** delivers alerts and messages to individual users and tracks whether they have been read.

**APIs:** `POST /notifications`, `GET /notifications/user/{user_id}`, `GET /notifications/{id}`, `PUT /notifications/{id}/read`, `GET /notifications/search`, `DELETE /notifications/{id}`.

**Database interaction:** the `notifications` table, with `user_id` as a foreign key to `users`. One user has many notifications.

**How notifications are generated.**

| Source | Type | Recipient |
|---|---|---|
| `POST /notifications` (Admin or Analyst) | any of the five types | the given user |
| Incident assigned (Service 3, Maya) | Incident Assignment | the assigned analyst |
| High/Critical vulnerability recorded (Service 7) | Vulnerability Alert | the owner of the affected asset |
| Response action assigned (Service 9) | System Notification | the assigned responder |

**Validation on creation:**
- all five fields are required;
- `notification_type` must be one of the five types and `severity_level` one of Low–Critical;
- `user_id` must be an existing user (`404`) whose account is Active. Suspended or inactive accounts are rejected with `400`, because nobody would read the alert.

Every notification starts as `Unread` with `read_date = NULL`, and `creation_date` is set by the database.

**Retrieve user notifications, including the empty result.**
1. The caller must be the user themself, an Administrator or an Auditor; otherwise `403` and a logged violation.
2. The route then checks that the user exists. An unknown id gives `404`, which distinguishes "no such user" from "no notifications".
3. It returns `{user, count, unread_count, notifications}` newest first.
4. A user with no notifications (`analyst_lina` in the seed data) gets `200` with `count: 0`, an empty list and the message "User 'analyst_lina' has no notifications". This is a valid, successful result, not an error.

**How a notification is marked as read.** `PUT /notifications/{id}/read` (no body):
- Only the recipient or an Administrator may mark it. An Analyst marking someone else's gets `403`, and an Auditor, who is read-only, gets `403`.
- It sets `status = 'Read'` and `read_date = datetime('now')` in one `UPDATE`.
- If the notification is already read, it returns `200` with "already read on …" and **keeps the original `read_date`**, so the first time the user saw the alert is preserved.

**Privacy rule.** Users see and read only their own notifications unless they are an Administrator or Auditor. This applies to `GET /notifications/{id}` and the user list. In search, Analysts and Regular Users are restricted to their own inbox automatically, and asking for another user returns `403`.

**Search.** `user` (numeric id or username), `type`, `severity` and `status`, combined with `AND` by `NotificationRepository.filter()`. All values are validated and bound as parameters.

**Deletion.** Administrator only; it writes `NOTIFICATION_DELETED` (Warning).

### Service 9: Security Playbook and Response Automation (Omar Obeid)

**Responsibility:** stores predefined incident-response procedures (playbooks) as ordered steps (response actions) and tracks who is doing each step and how far the response has progressed.

**APIs:** `POST /playbooks`, `GET /playbooks`, `GET /playbooks/{id}`, `POST /playbooks/{id}/actions`, `PUT /actions/{id}/status`, `DELETE /playbooks/{id}`.

**Database interaction:** `playbooks` (with `created_by` → `users`) and `response_actions` (with `playbook_id` → `playbooks ON DELETE CASCADE` and `assigned_user_id` → `users`). One playbook has many actions, and `UNIQUE (playbook_id, step_number)` applies.

**Creating a playbook.**
- All four fields are required.
- `incident_category` must be one of the incident categories of Service 3 (Malware Infection, Phishing Attack, …), so every playbook maps to a real incident type.
- `severity_level` must be Low–Critical.
- The name must be unique, case-insensitive (`409`).
- `created_by` is taken from the token, not from the body, so it cannot be faked.

**How response actions are ordered and kept unique.**
- `step_number` must be a positive integer.
- Before inserting, `step_taken()` checks whether the playbook already has that step. If it does, the API returns `409` and lists the existing steps. The `UNIQUE (playbook_id, step_number)` constraint is a second safety net in the database.
- Steps can be added in any order (e.g. 1, 3, then 2). `GET /playbooks/{id}` always returns them `ORDER BY step_number`, together with `progress {total_steps, completed_steps, percent_complete}`.
- An optional `assigned_user_id` must be an Active Security Administrator or Analyst (`400` for a Regular User or Auditor). The assignee receives a notification.

**How response action status updates work (PUT /actions/{id}/status).**
- **One step at a time.** The lifecycle is `Pending → In Progress → Completed`; skipping or going back returns `400`.
- **Steps run in order.** A step can only move to In Progress when every earlier step of the same playbook is Completed (`unfinished_before()`). Otherwise the API returns `409` and names the blocking steps, e.g. "Complete the earlier steps first: step 1 (Pending)".
- **Assignment.**
  - If the step has no assignee, whoever starts it becomes the assignee.
  - An Administrator can (re)assign any step to an Active Admin or Analyst.
  - An Analyst can only update steps assigned to them or unassigned ones, and can only assign themselves (`403` and a logged violation otherwise).
- **Completion date.** `Completed` sets `completion_date` to the current UTC time, or to the given `completion_date` (`YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`, not in the future). A completion date on a non-Completed status is rejected.
- The response contains `before`, `after` and the playbook's updated `progress`.

**Deleting a playbook.** Administrator only. Its response actions are deleted automatically by `ON DELETE CASCADE`. The response reports how many actions were removed, and `PLAYBOOK_DELETED` (Warning) is logged with that number.

---

## 6. Database Design: my tables (Omar Obeid)

**vulnerabilities**

| Field | Type | Notes |
|---|---|---|
| vulnerability_id | INTEGER | Primary key, autoincrement |
| title | TEXT | NOT NULL |
| description | TEXT | NOT NULL |
| cve_identifier | TEXT | NOT NULL, stored upper-case |
| cvss_score | REAL | `CHECK (cvss_score BETWEEN 0 AND 10)` |
| severity_level | TEXT | `CHECK IN ('Low','Medium','High','Critical')` |
| affected_asset_id | INTEGER | Foreign key → `assets(asset_id)`, `ON DELETE CASCADE` |
| discovery_source | TEXT | NOT NULL |
| status | TEXT | Default 'Open', `CHECK IN ('Open','Under Investigation','In Progress','Resolved','Closed')` |
| creation_date | TEXT | Default `datetime('now')` |
| resolution_date | TEXT | NULL until Resolved |

**notifications**

| Field | Type | Notes |
|---|---|---|
| notification_id | INTEGER | Primary key, autoincrement |
| user_id | INTEGER | Foreign key → `users(user_id)`, `ON DELETE CASCADE` |
| title | TEXT | NOT NULL |
| message | TEXT | NOT NULL |
| notification_type | TEXT | `CHECK` on the five types |
| severity_level | TEXT | `CHECK IN ('Low','Medium','High','Critical')` |
| status | TEXT | Default 'Unread', `CHECK IN ('Unread','Read')` |
| creation_date | TEXT | Default `datetime('now')` |
| read_date | TEXT | NULL until read |

**playbooks**

| Field | Type | Notes |
|---|---|---|
| playbook_id | INTEGER | Primary key, autoincrement |
| playbook_name | TEXT | NOT NULL, unique (enforced by the API, case-insensitive) |
| description | TEXT | NOT NULL |
| incident_category | TEXT | NOT NULL, one of the incident categories |
| severity_level | TEXT | `CHECK IN ('Low','Medium','High','Critical')` |
| created_by | INTEGER | Foreign key → `users(user_id)`, `ON DELETE SET NULL` |
| creation_date | TEXT | Default `datetime('now')` |

**response_actions**

| Field | Type | Notes |
|---|---|---|
| action_id | INTEGER | Primary key, autoincrement |
| playbook_id | INTEGER | Foreign key → `playbooks(playbook_id)`, `ON DELETE CASCADE` |
| action_description | TEXT | NOT NULL |
| step_number | INTEGER | NOT NULL, `UNIQUE (playbook_id, step_number)` |
| status | TEXT | Default 'Pending', `CHECK IN ('Pending','In Progress','Completed')` |
| assigned_user_id | INTEGER | Foreign key → `users(user_id)`, `ON DELETE SET NULL` |
| completion_date | TEXT | NULL until Completed |

**Relationships.**
- **Assets → Vulnerabilities (one-to-many).** An asset can have many vulnerabilities, and each vulnerability affects exactly one asset. `ON DELETE CASCADE` applies: a vulnerability has no meaning once its asset is removed from inventory.
- **Users → Notifications (one-to-many).** `ON DELETE CASCADE` applies: a deleted user's inbox is removed with them.
- **Users → Playbooks (created_by, one-to-many).** `ON DELETE SET NULL` keeps the playbook when its author leaves.
- **Playbooks → Response Actions (one-to-many, composition).** `ON DELETE CASCADE` applies: steps cannot exist without their playbook.
- **Users → Response Actions (assigned_user_id, one-to-many).** `ON DELETE SET NULL` returns the step to unassigned.

**Design decisions.**
- Every status and type is enforced twice: by API validation, which gives clear `400` messages, and by `CHECK` constraints, as a database safety net.
- Dates (`creation_date`, `read_date`, default `completion_date`/`resolution_date`) are generated by the server in UTC, not trusted from the client.
- Playbook progress is computed from the actions on every read rather than stored, so it can never be out of date.

---

## 7. Error Handling and Validation (Omar Obeid)

My services raise Maya's `ApiError`, so every error has the format `{"status":"error","message":...,"developer":"Omar Obeid","errors":{field: reason}}`.

| Code | Cases in my services |
|---|---|
| 400 | Missing/unknown fields; bad CVE format; CVSS out of range; severity not matching CVSS; invalid enum values; skipped or backward status transitions; read-only fields; invalid or future dates; bad search parameters; suspended recipient; assigning a step to a Regular User or Auditor |
| 401 | Missing or invalid token |
| 403 | Role not allowed; another user's notification; an Analyst updating another analyst's step |
| 404 | Vulnerability, asset, notification, user, playbook or action not found |
| 409 | Duplicate CVE on an asset; duplicate playbook name; duplicate step number; starting a step before earlier steps are completed |

**Security checks:**
- SQL injection: every value is a bound parameter, and only whitelisted column names appear in the SQL text.
- Empty and non-JSON bodies are rejected.
- `null` values on update are rejected.
- Every permission violation is written to the audit log.

---

## 9. Authentication and Authorization: my access rules (Omar Obeid)

| API | Admin | Analyst | Auditor | Regular User |
|---|---|---|---|---|
| POST /vulnerabilities, DELETE /vulnerabilities/{id} | ✔ | ✘ | ✘ | ✘ |
| GET /vulnerabilities, GET /vulnerabilities/{id}, GET /vulnerabilities/search | ✔ | ✔ | ✔ | ✘ |
| PUT /vulnerabilities/{id} | ✔ | ✔ | ✘ | ✘ |
| POST /notifications | ✔ | ✔ | ✘ | ✘ |
| GET /notifications/user/{id}, GET /notifications/{id}, GET /notifications/search | ✔ (all) | own | ✔ (all) | own |
| PUT /notifications/{id}/read | ✔ | own | ✘ | own |
| DELETE /notifications/{id} | ✔ | ✘ | ✘ | ✘ |
| POST /playbooks, DELETE /playbooks/{id} | ✔ | ✘ | ✘ | ✘ |
| GET /playbooks, GET /playbooks/{id} | ✔ | ✔ | ✔ | ✘ |
| POST /playbooks/{id}/actions | ✔ | ✔ | ✘ | ✘ |
| PUT /actions/{id}/status | ✔ | own/unassigned | ✘ | ✘ |

**How an authorization decision is made:**
1. The bearer token is verified (`401` if missing or invalid).
2. The role is compared with the route's `require_roles` list (`403` and an `UNAUTHORIZED_ACCESS` log).
3. Record-level rules are checked: notification owner, assigned analyst (`deny()` gives `403` and a log).
4. Only then does the route change data.

---

## Screenshot checklist (take these yourself in Postman, in collection order)

Caption format required by the spec: **"Omar Obeid – <API title> – <what it does>"**

1. Omar Obeid – Create Vulnerability Record – High, Critical and Medium records created (201), plus DB Browser showing the rows in `vulnerabilities`
2. Omar Obeid – Create Vulnerability Record – duplicate CVE on the same asset rejected (409)
3. Omar Obeid – Create Vulnerability Record – invalid CVE, CVSS out of range, severity/CVSS mismatch, missing fields (400), unknown asset (404)
4. Omar Obeid – Create Vulnerability Record – analyst denied (403)
5. Omar Obeid – Retrieve All Vulnerabilities – admin, analyst, auditor (200); regular user denied (403)
6. Omar Obeid – Retrieve Specific Vulnerability – existing (200) and non-existing (404)
7. Omar Obeid – Search Vulnerabilities – by CVE, severity, asset, status, combined, SQL injection, invalid input
8. Omar Obeid – Update Vulnerability Status – skipped transition rejected (400), then Open → Under Investigation → In Progress → Resolved (resolution date set) → Closed, plus DB row
9. Omar Obeid – Update Vulnerability Status – CVSS/severity/description update with before/after; read-only CVE rejected; auditor denied
10. Omar Obeid – Delete Vulnerability – analyst denied (403), admin success (200), then 404, plus the `VULNERABILITY_DELETED` row in `logs`
11. Omar Obeid – Create Notification – Security Alert, Threat Alert, System Notification (201), plus DB rows in `notifications`
12. Omar Obeid – Create Notification – invalid type / missing fields (400), unknown user (404), suspended user (400), regular user denied (403)
13. Omar Obeid – Retrieve User Notifications – own inbox, admin viewing another user, **empty result for analyst_lina (count 0)**, other user's inbox denied (403), unknown user (404)
14. Omar Obeid – Retrieve Specific Notification – own (200), someone else's (403), not found (404)
15. Omar Obeid – Mark Notification as Read – not the recipient (403), recipient (200, status Read + read_date), already read (200), plus DB row before and after
16. Omar Obeid – Search Notifications – by user, type, severity, status, combined, own inbox only for regular user, invalid status
17. Omar Obeid – Delete Notification – regular user denied (403), admin (200), then 404
18. Omar Obeid – Create Playbook – DDoS Mitigation and Data Leak Response (201); duplicate name (409); invalid / missing (400); analyst denied (403)
19. Omar Obeid – Retrieve All Playbooks – admin, analyst, auditor (200); regular user denied (403)
20. Omar Obeid – Add Response Action – steps 1, 3, 2 (201, assignee notified); duplicate step (409); invalid step / regular-user assignee (400); auditor denied (403); unknown playbook (404)
21. Omar Obeid – Retrieve Specific Playbook – actions returned in step order with progress
22. Omar Obeid – Update Response Action Status – skipped transition (400), out-of-order step (409), Pending → In Progress → Completed with completion date, another analyst's step denied (403), admin reassignment
23. Omar Obeid – Retrieve Specific Playbook – after progress (2 of 3 steps, 67%), plus the `response_actions` rows in DB Browser
24. Omar Obeid – Delete Playbook – analyst denied (403), admin (200, actions removed), then 404, plus DB Browser showing no actions left for that playbook
25. DB Browser for SQLite: structure of `vulnerabilities`, `notifications`, `playbooks` and `response_actions`
26. DB Browser for SQLite: `logs` filtered on my services (`related_service` = Vulnerability Management / Notification and Alert Management / Security Playbook and Response Automation)
27. GitHub: commit history filtered to my commits (author OhoBEiD)

---

## 11. References / AI usage (Omar Obeid)

- Flask documentation (flask.palletsprojects.com), SQLite documentation (foreign keys, `ON DELETE CASCADE`, `CHECK` constraints), the CVE ID syntax (cve.org), FIRST CVSS v3.1 specification (qualitative severity rating scale), Postman documentation.
- **AI usage:** I used Claude (Anthropic), an AI assistant, as a helper while building and documenting Services 7–9.
  - **Where AI was used:**
    - Generating the Python code for `vulnerabilities_service.py`, `notifications_service.py` and `playbooks_service.py`, the four models and repositories in `models.py`, and the CVE/CVSS/date validators, following the structure Maya and Zeinab had already built.
    - Generating the seed data for notifications and playbooks, the automated tests (`tests/test_services_7_9.py`) and the Postman collection.
    - Drafting the README API documentation and the text of my report sections.
  - **Purpose:** to implement and document my three services within the sprint deadline while following the specification closely (roles, validation, status transitions, error handling and evidence requirements), and to learn how a Flask REST backend is structured, tested and verified.
  - **What I did myself:** *(complete and adjust this list before submitting so it matches exactly what you did)*
    - Read the Sprint 1 specification, identified my services (7–9) and the parts of the team's code to reuse, and wrote the task description I gave to the AI.
    - Reviewed the generated code and pushed all my commits to the team repository from my own GitHub account (OhoBEiD).
    - Ran the automated test suite (49 tests passing) and every request of my Postman collection against my own running server.
    - Took all screenshots from my own system and checked the stored records against the database in DB Browser for SQLite.
