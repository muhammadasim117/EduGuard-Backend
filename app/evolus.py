"""Evolus integration: build an event from raw facts, ask the EduGuard agent, parse its JSON."""
import json
import os

from pathlib import Path

import httpx


def _decode(raw: bytes) -> str:
    """Windows editors sometimes save .env as UTF-16 or with a BOM; accept all of them."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig", errors="replace")


def load_env_file(path) -> int:
    """Tiny .env reader: KEY=VALUE, tolerates spaces and quotes. Real environment values win unless empty."""
    loaded = 0
    for line in _decode(Path(path).read_bytes()).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip().lstrip("\ufeff"), value.strip().strip('"').strip("'")
        if key and value and not os.environ.get(key):
            os.environ[key] = value
            loaded += 1
    return loaded


def _find_env():
    for p in (Path(__file__).resolve().parent.parent / ".env", Path.cwd() / ".env"):
        if p.is_file():
            return p
    return None


ENV_FILE = _find_env()
if ENV_FILE:
    load_env_file(ENV_FILE)

BASE_URL = os.environ.get("EVOLUS_BASE_URL", "https://api.evolus.ai/v1")
REQUIRED = ["incident_type", "risk_level", "evidence", "explanation",
            "recommended_action", "confidence", "needs_human_review"]
MAX_LOGS = int(os.environ.get("MAX_LOGS", "15"))


class EvolusError(RuntimeError):
    """Transport or authentication problem (not a bad model answer)."""


def is_configured() -> bool:
    return all(os.environ.get(k) for k in ("EVOLUS_APP_ID", "EVOLUS_API_KEY", "EVOLUS_AGENT_ID"))


def build_event(store, incident) -> dict:
    """Raw facts only. The incident title and the expected_* answer key are NOT sent to the agent."""
    uid = incident.user_id.lower()
    user = next(u for u in store.users if u.user_id.lower() == uid)
    perm = next((p for p in store.permissions if p.user_id.lower() == uid), None)
    students = {s.student_id: s for s in store.students}
    logs = sorted((l for l in store.access_logs if l.user_id.lower() == uid), key=lambda l: l.timestamp)

    summary = {"total_logs": len(logs), "by_action": {}, "by_result": {}}
    for l in logs:
        summary["by_action"][l.action] = summary["by_action"].get(l.action, 0) + 1
        summary["by_result"][l.result] = summary["by_result"].get(l.result, 0) + 1

    related = [l for l in logs if l.log_id == incident.related_log_id]
    recent = [l for l in logs if l.log_id != incident.related_log_id][-(MAX_LOGS - len(related)):]
    chosen = sorted(related + recent, key=lambda l: l.timestamp)

    def row(l):
        s = students.get(l.student_id)
        return {"log_id": l.log_id, "timestamp": l.timestamp, "action": l.action, "result": l.result,
                "student_id": l.student_id,
                "student_class": s.class_ if s else None,
                "student_district": s.district_id if s else None}

    return {
        "event_id": incident.incident_id,
        "flagged_log_id": incident.related_log_id,
        "user": user.model_dump(),
        "permissions": perm.model_dump() if perm else None,
        "access_summary": summary,
        "access_logs": [row(l) for l in chosen],
    }


def _parse(text: str) -> dict:
    data = json.loads(text[text.find("{"): text.rfind("}") + 1])
    missing = [k for k in REQUIRED if k not in data]
    if missing:
        raise ValueError(f"missing fields: {missing}")
    return data


def fallback(reason: str) -> dict:
    return {"incident_type": "unknown", "risk_level": "medium", "evidence": [],
            "explanation": "Automatic analysis could not be completed.",
            "recommended_action": "Review this event manually.",
            "confidence": 0.0, "needs_human_review": True, "error": reason}


def analyze_event(event: dict) -> dict:
    if not is_configured():
        raise EvolusError("Evolus is not configured: set EVOLUS_APP_ID, EVOLUS_API_KEY, EVOLUS_AGENT_ID")
    model = f'{os.environ["EVOLUS_APP_ID"]}:{os.environ["EVOLUS_AGENT_ID"]}'
    try:
        r = httpx.post(f"{BASE_URL}/chat/completions",
                       headers={"Authorization": f'Bearer {os.environ["EVOLUS_API_KEY"]}'},
                       json={"model": model, "messages": [{"role": "user", "content": json.dumps(event)}]},
                       timeout=float(os.environ.get("EVOLUS_TIMEOUT", "90")))
    except httpx.HTTPError as e:
        raise EvolusError(f"Could not reach Evolus: {e}")
    if r.status_code != 200:
        hints = {401: "invalid API key (use the application key)", 402: "Evolus credits exhausted",
                 404: "model id wrong (check appId:agentId)", 429: "rate limited, retry shortly"}
        raise EvolusError(f"Evolus returned {r.status_code}: {hints.get(r.status_code, r.text[:200])}")
    try:
        return _parse(r.json()["choices"][0]["message"]["content"])
    except Exception as e:
        return fallback(f"unparseable agent reply: {e}")


# ---------- direct AMD model (fallback, or the only path if ANALYSIS_PROVIDER=amd) ----------
AMD_DEFAULT_URL = "https://developer.amd.com.cn/radeon/api/v1"
SYSTEM_PROMPT = """You are EduGuard, a security and compliance analyst for a school district.
You receive one event: a user account, its permissions, and its access logs (with each student's class and district).
Decide whether it is a security risk. Respond with ONLY valid JSON, no other text:
{
  "incident_type": "departed_employee_access | excessive_permissions | out_of_class_access | bulk_export | cross_district_vendor_access | inactive_account | no_risk",
  "risk_level": "low | medium | high | critical",
  "evidence": ["specific facts from the event that support your finding"],
  "explanation": "2-3 plain-language sentences for a school administrator",
  "recommended_action": "one specific remediation for the administrator to approve",
  "confidence": 0.0,
  "needs_human_review": true
}
Rules:
- Use only facts in the event. Never invent users, dates or records.
- Compare each log's student_class with permissions.allowed_classes, and student_district with permissions.authorized_districts.
- Flag employment_status Inactive with an enabled account, permission_level above Standard for a teacher, and many exports in a short time.
- If evidence is unclear or incomplete, lower the confidence and set needs_human_review to true.
- Never claim an action was taken. You only recommend; the administrator approves."""


def amd_configured() -> bool:
    return bool(os.environ.get("AMD_API_KEY"))


def analyze_direct(event: dict) -> dict:
    if not amd_configured():
        raise EvolusError("AMD direct mode is not configured: set AMD_API_KEY")
    base = os.environ.get("AMD_BASE_URL", AMD_DEFAULT_URL).rstrip("/")
    model = os.environ.get("AMD_MODEL", "DeepSeek-V4.1-Flash")
    try:
        r = httpx.post(f"{base}/chat/completions",
                       headers={"Authorization": f'Bearer {os.environ["AMD_API_KEY"]}'},
                       json={"model": model, "max_tokens": 1200,
                             "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                          {"role": "user", "content": json.dumps(event)}]},
                       timeout=float(os.environ.get("AMD_TIMEOUT", "150")))
    except httpx.HTTPError as e:
        raise EvolusError(f"Could not reach the AMD model endpoint: {e}")
    if r.status_code != 200:
        raise EvolusError(f"AMD endpoint returned {r.status_code}: {r.text[:200]}")
    try:
        return _parse(r.json()["choices"][0]["message"]["content"])
    except Exception as e:
        return fallback(f"unparseable model reply: {e}")


def run_analysis(event: dict):
    """Returns (analysis, provider, note). ANALYSIS_PROVIDER: amd (default) | auto | evolus."""
    mode = os.environ.get("ANALYSIS_PROVIDER", "amd").lower()
    if mode == "amd":
        return analyze_direct(event), "amd_direct", None
    if mode == "evolus" or not amd_configured():
        return analyze_event(event), "evolus", None
    try:
        result = analyze_event(event)
        if not result.get("error"):
            return result, "evolus", None
        reason = f"Evolus reply unusable: {result['error']}"
    except EvolusError as e:
        reason = f"Evolus failed: {e}"
    return analyze_direct(event), "amd_direct", reason
