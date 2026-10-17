# Education Data Security API (mock school district)

FastAPI backend serving the **synthetic** school data (users, permissions, students, access logs,
incidents) from JSON files. The Evolus agent and the dashboard call this API.

## Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Docs (try every endpoint in the browser): http://127.0.0.1:8000/docs
Health + data check: http://127.0.0.1:8000/health

## Endpoints (IDs are case-insensitive: `U001` = `u001`)

| Method | Path | Filters |
|---|---|---|
| GET | `/users`, `/users/{user_id}` | `role`, `employment_status`, `account_status` |
| GET | `/permissions`, `/permissions/{user_id}` | `user_id` |
| GET | `/students`, `/students/{student_id}` | `class` (e.g. `Grade 6`) |
| GET | `/access-logs`, `/access-logs/{log_id}` | `user_id`, `student_id`, `action`, `result` (success/denied), `since`, `until`, `limit` |
| GET | `/incidents`, `/incidents/{incident_id}` | `user_id`, `expected_risk` |
| GET | `/health` | reports record counts and cross-file problems |
| POST | `/reload` | re-reads the JSON files without restarting |

`since` / `until` accept `2026-10-11` or `2026-10-11 10:00`.

## Data files (`data/`)

`users.json` (30), `permissions.json` (30), `students.json` (120), `access_logs.json` (288), `incidents.json` (5).

The district is fictional: 30 staff across 8 roles (Teacher, Principal, Vice Principal, Counselor, Registrar,
IT Admin, Substitute, Contractor), 120 students in Grades 4-8, and about two weeks of access logs
(5-13 Oct 2026) with 3 actions: `view_record`, `edit_record`, `export_record`.
Account statuses are `Active`, `Suspended` and `Disabled`.

### Seeded security incidents (matches the official MVP PDF)

| ID | Scenario | Risk |
|---|---|---|
| I001 | Former employee accessed student data | Critical |
| I002 | Teacher assigned excessive administrator-level permissions | High |
| I003 | Teacher accessed a student outside their assigned class | High |
| I004 | Bulk download of student records in a short period (100 exports in 10 minutes) | High |
| I005 | Vendor accessed student records outside its approved district | Critical |

Permissions explicitly include `permission_level` and `authorized_districts`; student records include `district_id` so elevated privileges and vendor tenant-boundary violations can be represented. The data includes normal activity alongside the five required incidents. The automated tests verify that each seeded incident is detectable and that ordinary activity stays clean.

### Regenerating the data

`python tools/generate_data.py` rewrites the five files (fixed random seed, so the result is always
identical). Edit that script to change the scenarios, then update the counts in `tests/test_api.py`.
Field names are served exactly as written in the files (the student field stays `class`).
To use files from another folder: `DATA_DIR=/path/to/folder uvicorn app.main:app`.

When the files change, call `POST /reload`. A file with a missing field or invalid JSON is
rejected with the file name and record number, and the previous data keeps being served.
`/health` also flags broken links between files (e.g. a log pointing at a user that doesn't exist).

## Verify it works

```bash
pytest -q                                   # 14 tests
newman run postman/education-security-api.postman_collection.json   # 23 requests, 42 checks
```

In Postman: Import the collection, then Run collection. Every request shows green/red checks.

## EduGuard analysis (Evolus agent)

Copy `.env.example` to `.env` and fill in `EVOLUS_APP_ID`, `EVOLUS_API_KEY` (application key) and `EVOLUS_AGENT_ID`.
`/health` shows `evolus_configured: true` when all three are set. Never commit `.env`.

| Method | Path | What it does |
|---|---|---|
| POST | `/incidents/{id}/analyze` | Sends raw facts (user, permissions, access logs with student class and district) to the Evolus agent and stores the analysis. The incident title and `expected_*` answer key are never sent. |
| GET | `/incidents/{id}/analysis`, `/analyses` | Stored analysis plus the administrator's decision |
| POST | `/incidents/{id}/decision` | Body `{"decision": "approve|reject|escalate", "decided_by": "...", "note": "..."}`. Nothing is executed automatically. |

Analyses are held in memory and are lost when the server restarts. Errors from Evolus (bad key, no credits, rate limit) return HTTP 502 with a hint; an unparseable agent reply is returned as a low-confidence analysis with `needs_human_review: true`.

### Provider modes (Evolus with AMD fallback)

Set `ANALYSIS_PROVIDER` in `.env`: `amd` (default, AMD direct only; Evolus is not needed), `auto` ( try the Evolus agent, and if it errors or times out after `EVOLUS_TIMEOUT` seconds, call the AMD model directly), or `evolus` (Evolus only). AMD direct needs `AMD_API_KEY`; the `.env` reader accepts UTF-8, UTF-16, BOM, spaces and quotes, and `/health` shows which `.env` file was loaded.
Every stored analysis has `provider` (`evolus` or `amd_direct`) and, when a fallback happened, `fallback_reason`, so the dashboard and the demo always show which path produced the result.
