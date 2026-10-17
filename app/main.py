"""Step 3: API endpoints. All data is read-only and synthetic."""
from typing import Optional

import os
from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from .models import AccessLog, Incident, Permission, Student, User
from . import evolus
from .store import DATA_DIR, store

app = FastAPI(
    title="Education Data Security API (mock school district)",
    description="Mock identity / SIS / access-log API for the Education Data Security Agent. All data is synthetic.",
    version="1.0.0",
)

# The dashboard runs on another port, so allow cross-origin calls (demo only).
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def _same(a: str, b: str) -> bool:
    """IDs are matched case-insensitively so u001 and U001 both work."""
    return a.strip().lower() == b.strip().lower()


def _find(items, key: str, value: str, label: str):
    for item in items:
        if _same(getattr(item, key), value):
            return item
    raise HTTPException(status_code=404, detail=f"{label} '{value}' not found")


def _normalize(ts: str, end_of_day: bool) -> str:
    """Accept 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM'. A date-only upper bound covers the whole day."""
    ts = ts.strip().replace("T", " ")
    if len(ts) == 10:
        return ts + (" 23:59" if end_of_day else " 00:00")
    return ts


# ---------- meta ----------
@app.get("/health", tags=["meta"])
def health():
    issues = store.integrity_issues()
    return {
        "status": "ok" if not issues else "data_issues",
        "data_dir": str(DATA_DIR),
        "records": store.counts(),
        "integrity_issues": issues,
        "evolus_configured": evolus.is_configured(),
        "amd_direct_configured": evolus.amd_configured(),
        "analysis_provider": os.environ.get("ANALYSIS_PROVIDER", "amd"),
        "env_file": str(evolus.ENV_FILE) if evolus.ENV_FILE else None,
    }


@app.post("/reload", tags=["meta"])
def reload_data():
    """Re-read the JSON files (after the data partner edits them). A bad file keeps the old data."""
    try:
        store.load()
    except RuntimeError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {"status": "reloaded", "records": store.counts()}


# ---------- users ----------
@app.get("/users", response_model=list[User], tags=["users"])
def list_users(
    role: Optional[str] = None,
    employment_status: Optional[str] = None,
    account_status: Optional[str] = None,
):
    result = store.users
    if role:
        result = [u for u in result if _same(u.role, role)]
    if employment_status:
        result = [u for u in result if _same(u.employment_status, employment_status)]
    if account_status:
        result = [u for u in result if _same(u.account_status, account_status)]
    return result


@app.get("/users/{user_id}", response_model=User, tags=["users"])
def get_user(user_id: str):
    return _find(store.users, "user_id", user_id, "User")


# ---------- permissions ----------
@app.get("/permissions", response_model=list[Permission], tags=["permissions"])
def list_permissions(user_id: Optional[str] = None):
    result = store.permissions
    if user_id:
        result = [p for p in result if _same(p.user_id, user_id)]
    return result


@app.get("/permissions/{user_id}", response_model=Permission, tags=["permissions"])
def get_permission(user_id: str):
    return _find(store.permissions, "user_id", user_id, "Permissions for user")


# ---------- students ----------
@app.get("/students", response_model=list[Student], response_model_by_alias=True, tags=["students"])
def list_students(class_name: Optional[str] = Query(None, alias="class", description="e.g. Grade 5")):
    result = store.students
    if class_name:
        result = [s for s in result if _same(s.class_, class_name)]
    return result


@app.get("/students/{student_id}", response_model=Student, response_model_by_alias=True, tags=["students"])
def get_student(student_id: str):
    return _find(store.students, "student_id", student_id, "Student")


# ---------- access logs ----------
@app.get("/access-logs", response_model=list[AccessLog], tags=["access-logs"])
def list_access_logs(
    user_id: Optional[str] = None,
    student_id: Optional[str] = None,
    action: Optional[str] = None,
    result: Optional[str] = Query(None, description="success or denied"),
    since: Optional[str] = Query(None, description="YYYY-MM-DD or YYYY-MM-DD HH:MM (inclusive)"),
    until: Optional[str] = Query(None, description="YYYY-MM-DD or YYYY-MM-DD HH:MM (inclusive)"),
    limit: int = Query(200, ge=1, le=5000),
):
    logs = store.access_logs
    if user_id:
        logs = [l for l in logs if _same(l.user_id, user_id)]
    if student_id:
        logs = [l for l in logs if _same(l.student_id, student_id)]
    if action:
        logs = [l for l in logs if _same(l.action, action)]
    if result:
        logs = [l for l in logs if _same(l.result, result)]
    if since:
        lo = _normalize(since, end_of_day=False)
        logs = [l for l in logs if l.timestamp >= lo]
    if until:
        hi = _normalize(until, end_of_day=True)
        logs = [l for l in logs if l.timestamp <= hi]
    return sorted(logs, key=lambda l: l.timestamp)[:limit]


@app.get("/access-logs/{log_id}", response_model=AccessLog, tags=["access-logs"])
def get_access_log(log_id: str):
    return _find(store.access_logs, "log_id", log_id, "Access log")


# ---------- incidents (the partner's seeded security scenarios) ----------
@app.get("/incidents", response_model=list[Incident], tags=["incidents"])
def list_incidents(user_id: Optional[str] = None, expected_risk: Optional[str] = None):
    result = store.incidents
    if user_id:
        result = [i for i in result if _same(i.user_id, user_id)]
    if expected_risk:
        result = [i for i in result if _same(i.expected_risk, expected_risk)]
    return result


@app.get("/incidents/{incident_id}", response_model=Incident, tags=["incidents"])
def get_incident(incident_id: str):
    return _find(store.incidents, "incident_id", incident_id, "Incident")


# ---------- EduGuard analysis (Evolus agent on the AMD-hosted model) ----------
ANALYSES: dict[str, dict] = {}  # incident_id -> {"analysis": {...}, "decision": {...} | None}


class Decision(BaseModel):
    decision: Literal["approve", "reject", "escalate"]
    decided_by: str = "administrator"
    note: str = ""


@app.post("/incidents/{incident_id}/analyze", tags=["analysis"])
def analyze_incident(incident_id: str):
    """Send the raw facts for this incident to the Evolus agent and store its analysis."""
    incident = _find(store.incidents, "incident_id", incident_id, "Incident")
    try:
        analysis, provider, note = evolus.run_analysis(evolus.build_event(store, incident))
    except evolus.EvolusError as e:
        raise HTTPException(status_code=502, detail=str(e))
    record = {"incident_id": incident.incident_id, "analysis": analysis, "decision": None,
              "provider": provider, "fallback_reason": note,
              "analyzed_at": datetime.now(timezone.utc).isoformat()}
    ANALYSES[incident.incident_id] = record
    return record


@app.get("/analyses", tags=["analysis"])
def list_analyses():
    return list(ANALYSES.values())


@app.get("/incidents/{incident_id}/analysis", tags=["analysis"])
def get_analysis(incident_id: str):
    incident = _find(store.incidents, "incident_id", incident_id, "Incident")
    if incident.incident_id not in ANALYSES:
        raise HTTPException(status_code=404, detail="Not analyzed yet: POST /incidents/{id}/analyze first")
    return ANALYSES[incident.incident_id]


@app.post("/incidents/{incident_id}/decision", tags=["analysis"])
def decide(incident_id: str, body: Decision):
    """Administrator approves, rejects or escalates the recommendation. Nothing is executed automatically."""
    incident = _find(store.incidents, "incident_id", incident_id, "Incident")
    if incident.incident_id not in ANALYSES:
        raise HTTPException(status_code=409, detail="Analyze the incident before deciding")
    ANALYSES[incident.incident_id]["decision"] = {**body.model_dump(),
                                                  "decided_at": datetime.now(timezone.utc).isoformat()}
    return ANALYSES[incident.incident_id]
