# Report Sections: Zeinab Harb (Services 4–6)

Draft text to paste into the common team report. Put "(Zeinab Harb)" next to each heading. Rewrite it in your own words where you want, and **take every screenshot yourself from your running system** (`python seed.py --reset`, `python app.py`, then run `postman/Zeinab_Harb_Services_4-6.postman_collection.json` in order).

---

## 5. Implementation Details (Zeinab Harb)

### Architecture of my services

My three services follow the same structure as Services 1–3. Each one is a Flask **Blueprint** (`threats_service.py`, `logs_service.py`, `reports_service.py`) registered in `app.py`, and they share the team's helpers:

- **Entity classes** `Threat` and `AuditLog` (dataclasses in `models.py`). Each holds its allowed values (`Threat.TYPES`, `Threat.SEVERITIES`, `AuditLog.SEVERITIES`) and a `to_dict()` method.
- **Repositories** `ThreatRepository` and `LogRepository`, which inherit from Maya's `BaseRepository`. They reuse the generic `get_by_id`, `get_all`, `insert`, `delete` and `search` methods and add their own:
  - `ThreatRepository.find_duplicate()` detects an existing type + value pair.
  - `LogRepository.for_user()` and `LogRepository.filter()` serve the log lookups.
  - `LogRepository` **overrides** `update()` to raise an error, so audit logs cannot be modified even from code (polymorphism).
- **Shared helpers** in `common.py`:
  - `require_roles` checks authentication and roles; I pass `service=` so violations are logged under my service.
  - `write_log()` records audit events.
  - `success()` / `error_body()` build the response format.
- **Developer name.** I added `set_developer(blueprint, name)` to `common.py`. A `before_request` hook stores `g.developer = "Zeinab Harb"` for my blueprints, and `success()`/`error_body()` read it. Every response from my services, including 401/403 errors raised before my code runs, shows `"developer": "Zeinab Harb"`. Maya's routes are unchanged.

**Communication between services.** All services run in one Flask application and share one SQLite database. Services 1–3, 4 and 7–9 call `write_log()` to send events to the Audit Logging Service. The Reports Service reads the tables owned by the other services (users, assets, incidents, threats, logs, vulnerabilities) with read-only SQL aggregate queries.

### Service 4: Threat Intelligence (Zeinab Harb)

**Responsibility:** stores known threat indicators (malicious IPs, suspicious domains, malware hashes, malware signatures and other indicators) so they can be used during incident investigation.

**APIs:** `POST /threats`, `GET /threats`, `GET /threats/{id}`, `GET /threats/search`, `PUT /threats/{id}`, `DELETE /threats/{id}` (see Section 8 / README for request and response formats).

**Database interaction:** the `threats` table. `INSERT` on create, `SELECT` on read and search (parameterised), `UPDATE` of description, severity and source, `DELETE` on delete.

**Add Threat Indicator: type and severity of each added threat.**

| # | Type | Value | Severity | Why this severity |
|---|---|---|---|---|
| 1 | IP Address | 192.0.2.10 | High → updated to Critical | Brute-forcing RDP on finance workstations is an active attack. It was raised to Critical once confirmed as a command-and-control address. |
| 2 | Domain | update-account-verify.net | Medium | Phishing domain. It needs a user to click, so it is not directly exploitable. |
| 3 | File Hash (SHA-256) | 8148eaa7…8e86 | Critical | Ransomware dropper: infection leads to data encryption and business outage. |
| 4 | Malware Signature | Adware.BrowserHelper.X | Low | Adware is a nuisance with low impact on confidentiality and integrity. |

The seed data adds 8 more indicators covering every type and every severity, such as a ransomware C2 IP (Critical), a phishing domain (High) and an sqlmap user agent (Other, Low).

**How validation works on insert.**

1. The body must be non-empty JSON with exactly the five fields. Missing fields give `400`; unknown fields give `400`.
2. `threat_type` and `severity_level` must be one of the allowed values.
3. `threat_value` is checked according to its type by `normalize_threat_value()`:
   - IPs with Python's `ipaddress` module;
   - domains with a regular expression (labels of letters/digits/hyphens, no leading or trailing hyphen, alphabetic TLD, at most 253 characters);
   - hashes must be hexadecimal with a length of 32, 40, 64 or 128 (MD5, SHA-1, SHA-256, SHA-512).
4. The value is normalised to a canonical form so that duplicates cannot hide behind formatting. IPs are compressed, and domains and hashes are lowercased (`EVIL.com` = `evil.com`).

**Threat indicator uniqueness.** Before inserting, `find_duplicate()` looks for the same type + value (case-insensitive). If one exists, the API returns `409 Conflict` with the id of the existing threat. The `UNIQUE (threat_type, threat_value)` constraint in `schema.sql` is a second safety net at the database level.

**Response format of GET /threats.** `{status, message, developer, data: {count, threats: [...]}}`. Each threat contains `threat_id, threat_type, threat_value, description, severity_level, source, date_added`, sorted by id.

**GET /threats/{id} responses.**
- Existing id → `200` with `"message": "Threat indicator found"` and the full threat.
- Non-existing id → `404` with `{"status":"error","message":"Threat indicator with id 99999 not found","developer":"Zeinab Harb"}`.
- A non-numeric id doesn't match the `<int:threat_id>` route, so it also returns 404.

**How search results are generated.**

1. Query parameters are mapped to a whitelist of columns:
   - `type` → `threat_type` and `severity` → `severity_level` (exact match, validated against the allowed values);
   - `value` → `threat_value` and `source` → `source` (partial, case-insensitive `LIKE %value%`).
2. Each parameter becomes one `WHERE` condition, and conditions are combined with `AND`.
3. Values are always bound as SQL parameters (`?`), so the injection attempt `value=' OR '1'='1` is treated as plain text and returns 0 results.
4. Unknown parameters, empty values, invalid enum values or no parameters at all return `400`.

**Validation applied during updates.**
- Only `description`, `severity_level` and `source` may be sent.
- `threat_type` / `threat_value` are read-only (`400`), because changing them would create a different indicator and could bypass the duplicate check. To change them, delete the indicator and add a new one.
- `severity_level` must be valid, and strings cannot be empty or exceed their length limits.
- The response contains `before` and `after`, and a `THREAT_UPDATED` log records each changed field (e.g. `severity_level: 'High' -> 'Critical'`).

**Deletion and unauthorized deletion prevention.** `DELETE /threats/{id}` is decorated with `@require_roles(ADMIN)`. An Analyst or Auditor gets `403`, and `require_roles` writes an `UNAUTHORIZED_ACCESS` (Warning) log. A successful deletion returns the deleted record and writes `THREAT_DELETED`.

**Role decision.** The spec's service table lists only `GET /threats` and `GET /threats/{id}` for the Auditor. The Auditor role description, however, includes "Search threat indicators". We followed the role description and allowed Auditors to search, which is still read-only.

### Service 5: Security Audit Logging (Zeinab Harb)

**Responsibility:** records and exposes security activity for accountability.

**APIs:** `POST /logs`, `GET /logs`, `GET /logs/{id}`, `GET /logs/search`, `DELETE /logs/{id}`, `GET /logs/user/{user_id}`.

**Database interaction:** the `logs` table (`user_id` is a foreign key to `users`). One user generates many logs.

**What events generate logs.** Logs are created automatically by `common.write_log()` from every service, plus manually through `POST /logs`.

| Event | Action | Severity | Service |
|---|---|---|---|
| Successful login | `LOGIN_SUCCESS` | Information | Users and Identity |
| Failed login (wrong password, unknown user, inactive account) | `LOGIN_FAILED` | Warning | Users and Identity |
| User created / deleted / updated | `USER_CREATED` / `USER_DELETED` / `USER_UPDATED` | Information / Warning | Users and Identity |
| Role change | `ROLE_CHANGED` | Warning | Users and Identity |
| Any permission violation (wrong role, not own record) | `UNAUTHORIZED_ACCESS` | Warning | the service that was called |
| Asset / incident changes | `ASSET_*`, `INCIDENT_*` | Information–Critical | Assets / Incidents |
| Threat changes | `THREAT_CREATED`, `THREAT_UPDATED`, `THREAT_DELETED` | Information / Warning | Threat Intelligence |
| Log deleted | `LOG_DELETED` | Warning | Security Audit Logging |
| Attempt to modify a log | `LOG_MODIFICATION_BLOCKED` | Warning | Security Audit Logging |

**Create Log Record.** `POST /logs` (Admin) adds events that happen outside the API, such as a malware scan or a blocked USB device. Validation:
- `user_id` must be an existing user (`404` otherwise);
- `action_performed` is normalised to UPPER_SNAKE_CASE (`USB device blocked` → `USB_DEVICE_BLOCKED`);
- `severity_level` must be Information, Warning, Error or Critical;
- `related_service` must be one of the nine service names;
- `timestamp` is set by the database (`datetime('now')`, UTC), so a client cannot back-date a log.

**Information displayed by GET /logs.** `data: {count, logs: [...]}`, newest first. Each log shows:
- `log_id`;
- `user_id` and `username`, i.e. who performed the action (from a join with the users table);
- `action_performed`;
- `description` (what exactly happened);
- `timestamp` (UTC);
- `severity_level`;
- `related_service` (which service produced it).

**GET /logs/{id} responses.** An existing id gives `200` with the record. An invalid id gives `404 "Log record with id 99999 not found"`.

**How filtering works (GET /logs/search).** `LogRepository.filter()` builds one `WHERE` condition per supplied parameter and joins them with `AND`. Every value is a bound parameter.

| Parameter | Condition | Notes |
|---|---|---|
| `user` | `user_id = ?` if numeric; `user_id IN (SELECT user_id FROM users WHERE username = ?)` if a username | |
| `date` | `date(timestamp) = ?` | Validated as `YYYY-MM-DD`; invalid → `400` |
| `action` | `action_performed LIKE %value%` | Case-insensitive |
| `severity` | `severity_level = ?` | Validated |
| `service` | `related_service LIKE %value%` | Case-insensitive |

**How logs are filtered by user id (GET /logs/user/{user_id}).**
1. The route first checks that the user exists. An unknown id gives `404`, which distinguishes "no such user" from "no activity".
2. It then runs `SELECT * FROM logs WHERE user_id = ? ORDER BY log_id DESC`.
3. The response includes the user's summary (`username`, `full_name`, `role`), the `count` and the logs.
4. A user with no activity (e.g. `analyst_lina`, who never logged in) returns `200` with `count: 0`, an empty list and the message "User 'analyst_lina' has no recorded activity".

**Audit log protection and access control for deletion.**
- **Preserve and never modify.** There is no update API. `PUT`/`PATCH /logs/{id}` returns `405 "Audit logs cannot be modified after creation"`, and the attempt itself is logged. In code, `LogRepository.update()` raises an error.
- **Only administrators delete.** `DELETE /logs/{id}` uses `@require_roles(ADMIN)`. Analysts, Auditors and Regular Users get `403`, and the attempt is logged as `UNAUTHORIZED_ACCESS`.
- **Traceable deletion.** A successful deletion writes a new `LOG_DELETED` record with the deleted log's action, severity and timestamp. Removing evidence therefore always leaves a trace.

**Roles:**
- Admin: all six APIs.
- Auditor: view all, view one, search, by user.
- Analyst: view one and search only (per the spec table).
- Regular User: none.

### Service 6: Security Reports (Zeinab Harb)

**Responsibility:** generates security statistics from the data of the other services. Reports are **read-only** and available to the **Security Administrator and Auditor only**. Analysts and Regular Users get `403`, and the attempt is logged.

**How information is collected from other services/tables.** Each report opens one database connection and runs aggregate SQL queries on the tables owned by the other services:

| Report | Source tables (service) | Main queries |
|---|---|---|
| Summary | users (1), assets (2), incidents (3), threats (4), logs (5), vulnerabilities (7) | `COUNT(*)` with conditions, e.g. `status NOT IN ('Resolved','Closed')` for open incidents and `severity_level='Critical'` for critical threats; last 5 logs joined with users |
| Incidents | incidents (3) | `COUNT(*)`, `GROUP BY severity`, `GROUP BY status`, `GROUP BY category`, `assigned_analyst_id IS NULL` |
| Assets | assets (2) | `COUNT(*)`, `criticality_level='Critical'`, `GROUP BY asset_type / criticality_level / status` |
| Threats | threats (4) | `COUNT(*)`, `GROUP BY severity_level`, `GROUP BY threat_type`, `ORDER BY date_added DESC LIMIT 5` |
| Vulnerabilities | vulnerabilities (7) joined with assets (2) | `COUNT(*)`, `GROUP BY severity_level / status`, `AVG(cvss_score)`, critical list with the affected asset name |
| Activity | logs (5) joined with users (1) | `COUNT(*)`; counts of `LOGIN_SUCCESS`, `LOGIN_FAILED`, `UNAUTHORIZED_ACCESS`; `GROUP BY action_performed ORDER BY count DESC LIMIT 5`; `GROUP BY user_id`; `GROUP BY severity_level / related_service` |

Grouped results always list **every allowed value, including zeros**. For example, the vulnerability report shows `"Low": 0`, so the reader can see that a category is empty rather than missing. The sum of each group always equals the total.

**Threat report: how threat data is collected.** The report reads the `threats` table maintained by the Threat Intelligence Service. "Threats grouped by severity" and "by type" are `GROUP BY` counts. "Recently added threats" are the 5 newest rows by `date_added`.

**Vulnerability report: how vulnerability data is collected.** The report reads the `vulnerabilities` table maintained by the Vulnerability Management Service (Service 7) and joins `assets` to show the affected asset's name for each critical vulnerability. Until Service 7's API is complete, `seed.py` inserts 6 sample vulnerabilities with different severities and statuses.

**Activity report: how audit logs are analysed.**
- *Total user activities* = number of rows in `logs`.
- *Login attempts* = `LOGIN_SUCCESS` + `LOGIN_FAILED`. *Failed login attempts* = rows with `LOGIN_FAILED`, including attempts on unknown usernames, which have no `user_id`.
- *Most performed actions* = `GROUP BY action_performed ORDER BY COUNT(*) DESC`, top 5.
- *Most active users* = `GROUP BY user_id` joined with `users` to show usernames.

Successful report generation is deliberately **not** logged, so viewing a report does not change the activity numbers it reports.

**Verifying report values against the database.** Run these queries in DB Browser for SQLite and compare them with the report screenshots:

```sql
-- Threat report
SELECT COUNT(*) FROM threats;
SELECT severity_level, COUNT(*) FROM threats GROUP BY severity_level;
SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type;
-- Vulnerability report
SELECT severity_level, COUNT(*) FROM vulnerabilities GROUP BY severity_level;
SELECT status, COUNT(*) FROM vulnerabilities GROUP BY status;
SELECT ROUND(AVG(cvss_score), 2) FROM vulnerabilities;
-- Activity report
SELECT COUNT(*) FROM logs;
SELECT action_performed, COUNT(*) FROM logs GROUP BY action_performed ORDER BY 2 DESC;
-- Summary report
SELECT COUNT(*) FROM incidents WHERE status NOT IN ('Resolved', 'Closed');
SELECT COUNT(*) FROM threats WHERE severity_level = 'Critical';
```

The automated tests (`tests/test_services_4_6.py`) also compare each report with these queries.

---

## 6. Database Design: my tables (Zeinab Harb)

**threats**

| Field | Type | Notes |
|---|---|---|
| threat_id | INTEGER | Primary key, autoincrement |
| threat_type | TEXT | `CHECK IN ('IP Address','Domain','File Hash','Malware Signature','Other')` |
| threat_value | TEXT | NOT NULL, stored normalised |
| description | TEXT | NOT NULL |
| severity_level | TEXT | `CHECK IN ('Low','Medium','High','Critical')` |
| source | TEXT | NOT NULL |
| date_added | TEXT | Default `datetime('now')` |

`UNIQUE (threat_type, threat_value)` prevents duplicate indicators.

**logs**

| Field | Type | Notes |
|---|---|---|
| log_id | INTEGER | Primary key, autoincrement |
| user_id | INTEGER | Foreign key → `users(user_id)`, `ON DELETE SET NULL` |
| action_performed | TEXT | NOT NULL |
| description | TEXT | NOT NULL |
| timestamp | TEXT | Default `datetime('now')` |
| severity_level | TEXT | `CHECK IN ('Information','Warning','Error','Critical')` |
| related_service | TEXT | NOT NULL |

**Relationship: Users → Logs (one-to-many).** One user generates many audit records, and each record belongs to at most one user. `ON DELETE SET NULL` keeps the audit trail when a user account is deleted, because deleting a user must not erase the evidence of what they did. `user_id` may also be NULL for failed logins with an unknown username.

**Design decisions.**
- Threat types and severities are enforced twice, by API validation (clear `400` messages) and by `CHECK` constraints (database safety net).
- Threat values are normalised before storage so the UNIQUE constraint is meaningful.
- Timestamps are generated by the database, not the client.
- Reports have no table of their own: they are computed live from current data, so they can never be out of date.

---

## 7. Error Handling and Validation (Zeinab Harb)

- My services raise Maya's `ApiError`, so errors use the same `{"status":"error","message":...,"developer":"Zeinab Harb","errors":{field: reason}}` format.

| Code | Cases in my services |
|---|---|
| 400 | Validation, unknown fields or parameters, read-only fields, bad dates |
| 401 | Missing or invalid token |
| 403 | Role not allowed |
| 404 | Threat, log or user not found |
| 405 | Log modification |
| 409 | Duplicate threat |

- **Threat validation:** required fields; type and severity enums; IP, domain and hash formats; string lengths; duplicate detection; read-only fields on update.
- **Log validation:** positive integer `user_id` that must exist; action format; severity and service enums; date format for search.
- **Security checks:**
  - SQL injection: every value is a bound parameter, and only whitelisted column names appear in SQL text.
  - Empty requests and unexpected fields are rejected.
  - Every permission violation is logged.

---

## 9. Authentication and Authorization: my access rules (Zeinab Harb)

| API | Admin | Analyst | Auditor | Regular User |
|---|---|---|---|---|
| POST /threats, PUT/DELETE /threats/{id} | ✔ | ✘ | ✘ | ✘ |
| GET /threats, GET /threats/{id}, GET /threats/search | ✔ | ✔ | ✔ | ✘ |
| POST /logs, DELETE /logs/{id} | ✔ | ✘ | ✘ | ✘ |
| GET /logs, GET /logs/user/{id} | ✔ | ✘ | ✔ | ✘ |
| GET /logs/{id}, GET /logs/search | ✔ | ✔ | ✔ | ✘ |
| GET /reports/* | ✔ | ✘ | ✔ | ✘ |

**How an authorization decision is made:** the bearer token is checked (`401`), then the role is compared with the route's `require_roles` list (`403` and an `UNAUTHORIZED_ACCESS` log), and only then does the route run.

---

## Screenshot checklist (take these yourself in Postman, in collection order)

Caption format required by the spec: **"Zeinab Harb – <API title> – <what it does>"**

1. Zeinab Harb – Add Threat Indicator – IP (High), Domain (Medium), File Hash (Critical), Malware Signature (Low) added (201), plus DB Browser showing the rows in `threats`
2. Zeinab Harb – Add Threat Indicator – duplicate type + value rejected (409)
3. Zeinab Harb – Add Threat Indicator – invalid IP / domain / hash / missing fields rejected (400)
4. Zeinab Harb – Add Threat Indicator – analyst denied (403)
5. Zeinab Harb – Retrieve All Threat Indicators – admin, analyst, auditor (200); regular user denied (403)
6. Zeinab Harb – Retrieve Specific Threat Indicator – existing (200) and non-existing (404)
7. Zeinab Harb – Search Threat Indicators – by type, severity, source, value, combined, invalid severity, SQL injection
8. Zeinab Harb – Update Threat Information – before, update, after (+ DB row)
9. Zeinab Harb – Update Threat Information – read-only value / invalid severity rejected (400)
10. Zeinab Harb – Delete Threat Indicator – analyst denied (403), admin success (200), then 404
11. Zeinab Harb – Create Log Record – logs for analyst, regular user, auditor, admin (201) + DB rows in `logs`
12. Zeinab Harb – Create Log Record – invalid input (400), unknown user (404), auditor denied (403)
13. Zeinab Harb – Retrieve All Logs – admin / auditor (200), analyst denied (403)
14. Zeinab Harb – Retrieve Specific Log – existing (200), invalid id (404)
15. Zeinab Harb – Search Logs – by user, date, action, severity, service, combined, invalid date
16. Zeinab Harb – Retrieve Logs By User – user with logs, user with no logs (count 0), unknown user (404)
17. Zeinab Harb – Modify Log – blocked (405)
18. Zeinab Harb – Delete Logs – analyst/auditor denied (403), admin success (200) + LOG_DELETED row in DB
19. Zeinab Harb – Generate Security Summary Report – admin and auditor
20. Zeinab Harb – Generate Incident / Asset Report
21. Zeinab Harb – Generate Threat Report – plus DB Browser query results showing matching counts
22. Zeinab Harb – Generate Vulnerability Report – plus DB Browser query results showing matching counts
23. Zeinab Harb – Generate Activity Report – plus DB Browser query results showing matching counts
24. Zeinab Harb – Generate Reports – analyst and regular user denied (403)
25. DB Browser for SQLite: structure of the `threats` and `logs` tables
26. GitHub: commit history filtered to my commits

---

## 11. References / AI usage (Zeinab Harb)

- Flask documentation (flask.palletsprojects.com), Python `ipaddress` and `re` modules, SQLite documentation (aggregate functions, `date()`), Postman documentation.
- **AI usage:** I used Claude (Anthropic), an AI assistant, as a helper while building and documenting Services 4–6. It did not do the whole task: I set up, ran, tested and verified the system myself and produced all the evidence from my own machine.
  - **Where AI was used:**
    - Generating the Python code for `threats_service.py`, `logs_service.py` and `reports_service.py`, the `Threat`/`AuditLog` models and repositories, the threat validators and the developer-name change in `common.py`, following the structure Maya had already built.
    - Generating the seed data for threats and sample vulnerabilities, the automated tests (`tests/test_services_4_6.py`) and the Postman collection.
    - Drafting the README API documentation and the text of my report sections.
    - Guiding me step by step through running the Postman requests and DB Browser checks, and compiling my screenshots into the captioned evidence document.
  - **Purpose:** to implement and document my three services within the sprint deadline while following the specification closely (roles, validation, error handling and evidence requirements), and to learn how a Flask REST backend is tested and verified with Postman and a database browser.
  - **What I did myself:**
    - Read the Sprint I specification, identified my services (4–6) and the parts of Maya's code to reuse, and wrote the task description I gave to the AI.
    - Set up the project on my laptop (virtual environment, dependencies, database seeding), applied the changes and pushed all my commits to the team repository from my own GitHub account.
    - Ran the automated test suite (32 tests passing) and ran every API request in Postman against my own running server, checking each status code and response.
    - Took all the screenshots (73 figures) from my own system and checked the stored records, log entries and report numbers against the database in DB Browser for SQLite.
    - Committed the evidence document and prepared my sections for the team report.
