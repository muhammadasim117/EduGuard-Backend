import json

from fastapi.testclient import TestClient

from app import evolus
from app.main import ANALYSES, app
from app.store import store

client = TestClient(app)
GOOD = {"incident_type": "departed_employee_access", "risk_level": "critical", "evidence": ["x"],
        "explanation": "e", "recommended_action": "Disable the account", "confidence": 0.9,
        "needs_human_review": False}


def test_event_hides_the_answer_key_and_has_raw_facts():
    ev = evolus.build_event(store, store.incidents[0])
    blob = json.dumps(ev)
    assert "expected_" not in blob and store.incidents[0].title not in blob
    assert ev["user"]["employment_status"] == "Inactive"
    assert ev["flagged_log_id"] in [l["log_id"] for l in ev["access_logs"]]
    assert all(len(evolus.build_event(store, i)["access_logs"]) <= evolus.MAX_LOGS for i in store.incidents)


def test_analyze_then_decide(monkeypatch):
    monkeypatch.setattr(evolus, "analyze_direct", lambda ev: GOOD)
    r = client.post("/incidents/i001/analyze")
    assert r.status_code == 200 and r.json()["analysis"]["risk_level"] == "critical"
    assert client.get("/incidents/I001/analysis").json()["decision"] is None
    d = client.post("/incidents/I001/decision", json={"decision": "approve", "decided_by": "admin"})
    assert d.json()["decision"]["decision"] == "approve"
    ANALYSES.clear()


def test_decision_requires_analysis_and_valid_value():
    ANALYSES.clear()
    assert client.post("/incidents/I002/decision", json={"decision": "approve"}).status_code == 409
    assert client.post("/incidents/I002/decision", json={"decision": "delete"}).status_code == 422


def test_bad_agent_reply_becomes_human_review_not_a_crash():
    assert evolus._parse(json.dumps(GOOD))["risk_level"] == "critical"
    assert evolus.fallback("x")["needs_human_review"] is True


def test_missing_config_returns_502(monkeypatch):
    for k in ("EVOLUS_APP_ID", "EVOLUS_API_KEY", "EVOLUS_AGENT_ID", "AMD_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    r = client.post("/incidents/I003/analyze")
    assert r.status_code == 502 and "not configured" in r.json()["detail"]


def _boom(ev):
    raise evolus.EvolusError("Evolus returned 422: endpoint_error")


def test_auto_falls_back_to_amd_when_evolus_fails(monkeypatch):
    ANALYSES.clear()
    monkeypatch.setenv("AMD_API_KEY", "x")
    monkeypatch.setenv("ANALYSIS_PROVIDER", "auto")
    monkeypatch.setattr(evolus, "analyze_event", _boom)
    monkeypatch.setattr(evolus, "analyze_direct", lambda ev: GOOD)
    r = client.post("/incidents/I001/analyze").json()
    assert r["provider"] == "amd_direct" and "Evolus failed" in r["fallback_reason"]
    ANALYSES.clear()


def test_auto_uses_evolus_when_it_works(monkeypatch):
    ANALYSES.clear()
    monkeypatch.setenv("AMD_API_KEY", "x")
    monkeypatch.setattr(evolus, "analyze_event", lambda ev: GOOD)
    monkeypatch.setattr(evolus, "analyze_direct", lambda ev: 1 / 0)
    monkeypatch.setenv("ANALYSIS_PROVIDER", "auto")
    assert client.post("/incidents/I001/analyze").json()["provider"] == "evolus"
    ANALYSES.clear()


def test_amd_only_mode_skips_evolus_and_evolus_only_mode_has_no_fallback(monkeypatch):
    ANALYSES.clear()
    monkeypatch.setenv("AMD_API_KEY", "x")
    monkeypatch.setattr(evolus, "analyze_event", _boom)
    monkeypatch.setattr(evolus, "analyze_direct", lambda ev: GOOD)
    monkeypatch.setenv("ANALYSIS_PROVIDER", "amd")
    assert client.post("/incidents/I001/analyze").json()["provider"] == "amd_direct"
    monkeypatch.setenv("ANALYSIS_PROVIDER", "evolus")
    assert client.post("/incidents/I001/analyze").status_code == 502
    ANALYSES.clear()


def test_direct_prompt_does_not_leak_answer_key():
    assert "expected_" not in evolus.SYSTEM_PROMPT


def test_default_mode_is_amd_direct_and_needs_no_evolus(monkeypatch):
    ANALYSES.clear()
    for k in ("ANALYSIS_PROVIDER", "EVOLUS_APP_ID", "EVOLUS_API_KEY", "EVOLUS_AGENT_ID"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(evolus, "analyze_direct", lambda ev: GOOD)
    monkeypatch.setattr(evolus, "analyze_event", _boom)
    assert client.post("/incidents/I001/analyze").json()["provider"] == "amd_direct"
    ANALYSES.clear()


def test_env_loader_handles_utf16_spaces_quotes_and_bom(tmp_path, monkeypatch):
    for k in ("T_A", "T_B", "T_C"):
        monkeypatch.delenv(k, raising=False)
    f = tmp_path / ".env"
    f.write_bytes("T_A = 'one'\r\n# note\r\nT_B=\"two\"\r\n".encode("utf-16"))
    assert evolus.load_env_file(f) == 2
    import os
    assert os.environ["T_A"] == "one" and os.environ["T_B"] == "two"
    f.write_bytes(b"\xef\xbb\xbfT_C=three\n")
    assert evolus.load_env_file(f) == 1 and os.environ["T_C"] == "three"
    for k in ("T_A", "T_B", "T_C"):
        monkeypatch.delenv(k, raising=False)
