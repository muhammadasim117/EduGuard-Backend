import json
from datetime import datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
DATA = Path(__file__).resolve().parent.parent / "data"


def file_records(name):
    return json.loads((DATA / name).read_text())


def ids(resp, key):
    return [x[key] for x in resp.json()]


# ---- the API returns exactly what is in the files ----
def test_every_endpoint_matches_its_file():
    assert client.get("/users").json() == file_records("users.json")
    assert client.get("/permissions").json() == file_records("permissions.json")
    assert client.get("/students").json() == file_records("students.json")
    assert client.get("/incidents").json() == file_records("incidents.json")
    api_logs = client.get("/access-logs", params={"limit": 5000}).json()
    assert sorted(api_logs, key=lambda l: l["log_id"]) == sorted(file_records("access_logs.json"), key=lambda l: l["log_id"])


def test_health_and_data_integrity():
    h = client.get("/health").json()
    assert h["status"] == "ok"
    assert h["integrity_issues"] == []
    assert h["records"] == {"users": 30, "permissions": 30, "students": 120, "access_logs": 288, "incidents": 5}


def test_data_is_varied_enough_for_a_demo():
    users = file_records("users.json")
    assert len({u["role"] for u in users}) >= 6
    assert {u["account_status"] for u in users} >= {"Active", "Suspended", "Disabled"}
    assert {l["action"] for l in file_records("access_logs.json")} >= {"view_record", "edit_record", "export_record"}
    assert {i["expected_risk"] for i in file_records("incidents.json")} == {"Critical", "High"}
    assert {s["class"] for s in file_records("students.json")} == {f"Grade {n}" for n in range(4, 9)}


# ---- users ----
def test_users_filters_and_detail():
    inactive = client.get("/users", params={"employment_status": "Inactive"}).json()
    assert [u["user_id"] for u in inactive] == ["U002", "U011", "U017"]
    assert len(client.get("/users", params={"role": "teacher"}).json()) == 18  # case-insensitive
    assert ids(client.get("/users", params={"account_status": "Suspended"}), "user_id") == ["U016"]
    assert client.get("/users/U003").json()["name"] == "Sam Wilson"
    assert client.get("/users/u003").json()["name"] == "Sam Wilson"
    assert client.get("/users/U999").status_code == 404


# ---- permissions ----
def test_permissions():
    assert client.get("/permissions/U003").json()["allowed_classes"] == ["Grade 5", "Grade 6", "Grade 7"]
    assert client.get("/permissions", params={"user_id": "U001"}).json()[0]["allowed_classes"] == ["Grade 5"]
    assert client.get("/permissions/U029").json()["can_view_student_records"] is False
    assert client.get("/permissions/U018").json()["permission_level"] == "Administrator"
    assert client.get("/permissions/U029").json()["authorized_districts"] == ["North District"]
    assert client.get("/permissions/U999").status_code == 404


# ---- students ----
def test_students_use_class_key_and_filter():
    s = client.get("/students/S003").json()
    assert s["student_id"] == "S003" and s["class"] == "Grade 6" and s["name"]
    assert s["district_id"] == "Central District"
    grade6 = client.get("/students", params={"class": "Grade 6"}).json()
    assert len(grade6) == 24 and {x["class"] for x in grade6} == {"Grade 6"}
    assert {"S003", "S004"} <= {x["student_id"] for x in grade6}
    assert client.get("/students/S999").status_code == 404


# ---- access logs ----
def test_access_logs_filters():
    assert ids(client.get("/access-logs", params={"user_id": "U001", "since": "2026-10-11", "until": "2026-10-11"}), "log_id") == ["L001", "L003", "L005"]
    denied = ids(client.get("/access-logs", params={"result": "denied"}), "log_id")
    assert "L005" in denied and len(denied) == 1
    assert ids(client.get("/access-logs", params={"student_id": "S004", "since": "2026-10-11", "until": "2026-10-11"}), "log_id") == ["L004", "L005"]
    assert len(client.get("/access-logs", params={"limit": 2}).json()) == 2
    assert client.get("/access-logs", params={"limit": 0}).status_code == 422
    assert client.get("/access-logs/L003").json()["student_id"] == "S001"
    assert client.get("/access-logs/L999").status_code == 404
    exports = client.get("/access-logs", params={"action": "export_record"}).json()
    assert len(exports) == 107 and all(l["action"] == "export_record" for l in exports)


def test_access_logs_are_sorted_by_time():
    stamps = [l["timestamp"] for l in client.get("/access-logs", params={"limit": 5000}).json()]
    assert stamps == sorted(stamps)


def test_access_log_date_filters():
    day = client.get("/access-logs", params={"since": "2026-10-11", "until": "2026-10-11"}).json()
    assert len(day) == 5  # date-only upper bound includes the whole day (weekend: only the starter logs)
    assert client.get("/access-logs", params={"until": "2026-10-04"}).json() == []
    window = ids(client.get("/access-logs", params={"since": "2026-10-11 10:00", "until": "2026-10-11 10:10"}), "log_id")
    assert window == ["L003", "L004"]


# ---- incidents ----
def test_incidents():
    high = ids(client.get("/incidents", params={"expected_risk": "High"}), "incident_id")
    assert high == ["I002", "I003", "I004"]
    assert ids(client.get("/incidents", params={"expected_risk": "Critical"}), "incident_id") == ["I001", "I005"]
    assert client.get("/incidents/I001").json()["expected_risk"] == "Critical"
    assert ids(client.get("/incidents", params={"user_id": "U001"}), "incident_id") == ["I003"]
    assert client.get("/incidents/I999").status_code == 404


# ---- end-to-end proof: the security rules, using ONLY the API, flag exactly the seeded incidents ----
def _flagged_logs():
    """Apply simple security rules to every log. Returns {log_id: set(reasons)}."""
    users = {u["user_id"]: u for u in client.get("/users").json()}
    perms = {p["user_id"]: p for p in client.get("/permissions").json()}
    students = {s["student_id"]: s for s in client.get("/students").json()}
    logs = client.get("/access-logs", params={"limit": 5000}).json()
    flagged = {}

    def flag(log, why):
        flagged.setdefault(log["log_id"], set()).add(why)

    for l in logs:
        u, p, s = users[l["user_id"]], perms[l["user_id"]], students[l["student_id"]]
        hhmm = l["timestamp"][11:]
        if l["result"] == "denied":
            flag(l, "denied")
        if u["employment_status"] != "Active":
            flag(l, "inactive_employee")
        if u["account_status"] != "Active":
            flag(l, "account_not_active")
        if l["result"] == "success" and not p["can_view_student_records"]:
            flag(l, "no_record_permission")
        if u["role"] == "Teacher" and p.get("permission_level") == "Administrator":
            flag(l, "excessive_permissions")
        if l["result"] == "success" and s.get("district_id", "Central District") not in p.get("authorized_districts", ["Central District"]):
            flag(l, "vendor_outside_district")
        if l["result"] == "success" and s["class"] not in p["allowed_classes"]:
            flag(l, "outside_class")
        if hhmm < "07:30" or hhmm > "17:00":
            flag(l, "after_hours")
    # bulk access: 10+ successful accesses by one user within 15 minutes
    by_user = {}
    for l in logs:
        if l["result"] == "success":
            by_user.setdefault(l["user_id"], []).append(l)
    for user_logs in by_user.values():
        times = [datetime.strptime(l["timestamp"], "%Y-%m-%d %H:%M") for l in user_logs]
        for i, l in enumerate(user_logs):
            window = [x for x, t in zip(user_logs, times) if timedelta(0) <= t - times[i] <= timedelta(minutes=15)]
            if len(window) >= 10:
                for x in window:
                    flag(x, "bulk_access")
    return flagged, logs


def test_security_rules_flag_exactly_the_seeded_incidents():
    flagged, logs = _flagged_logs()
    incidents = client.get("/incidents").json()
    log_user = {l["log_id"]: l["user_id"] for l in logs}
    # 1) every seeded incident's log is caught by at least one rule
    for inc in incidents:
        assert inc["related_log_id"] in flagged, f"{inc['incident_id']} is not detectable by any rule"
        assert log_user[inc["related_log_id"]] == inc["user_id"]
    # 2) nothing else is flagged: all normal traffic is clean (no false alarms)
    incident_users = {i["user_id"] for i in incidents}
    incident_log_ids = {i["related_log_id"] for i in incidents}
    # Every seeded incident is flagged; the starter denied-attempt log is an extra security signal.
    assert incident_log_ids <= set(flagged)
    bulk_scenario_ids = {l["log_id"] for l in logs if l["user_id"] == "U012" and l["timestamp"].startswith("2026-10-13 10:")}
    normal_log_ids = {l["log_id"] for l in logs} - incident_log_ids - bulk_scenario_ids - {"L005"}
    assert not (normal_log_ids & set(flagged)), f"Normal logs incorrectly flagged: {normal_log_ids & set(flagged)}"


def test_partner_security_checks_reproduce_through_api():
    flagged, _ = _flagged_logs()
    incident_map = {i["incident_id"]: i for i in client.get("/incidents").json()}
    assert "inactive_employee" in flagged[incident_map["I001"]["related_log_id"]]
    assert "excessive_permissions" in flagged[incident_map["I002"]["related_log_id"]]
    assert "outside_class" in flagged[incident_map["I003"]["related_log_id"]]
    assert "bulk_access" in flagged[incident_map["I004"]["related_log_id"]]
    assert "vendor_outside_district" in flagged[incident_map["I005"]["related_log_id"]]
    assert "L001" not in flagged and "L004" not in flagged  # normal starter logs stay clean


# ---- reload behaviour ----
def test_reload_ok():
    assert client.post("/reload").json()["status"] == "reloaded"


def test_bad_file_is_rejected_and_old_data_kept(tmp_path, monkeypatch):
    import shutil
    from app import store as store_module

    for f in DATA.glob("*.json"):
        shutil.copy(f, tmp_path / f.name)
    (tmp_path / "users.json").write_text('[{"user_id": "U001"}]')  # missing required fields
    monkeypatch.setattr(store_module, "DATA_DIR", tmp_path)
    r = client.post("/reload")
    assert r.status_code == 422
    assert "users.json record #1" in r.json()["detail"]
    assert len(client.get("/users").json()) == 30  # old data still served
