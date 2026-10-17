"""Generate the synthetic school-district data (all names are made up).

Run from the project root:   python tools/generate_data.py
It rewrites data/*.json. The output is deterministic (fixed random seed), so everyone on the
team gets identical files. Field names are unchanged from the original starter files.

Design:
  * "Normal" activity: active staff viewing/editing/exporting only students in their allowed
    classes, on weekdays, 08:00-16:30. Every normal log is clean, so it triggers NO security rule.
  * "Seeded" activity: 5 incidents (I001-I005; I006-I012 are optional extras). Every seeded log is tied to an incident, and the
    test suite proves that the security rules flag exactly those and nothing else.
"""
import json
import random
from datetime import date, datetime, timedelta
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"

# Official MVP scope: I001-I005, matching the team PDF.
# I001 is represented by the starter log L002; I002-I005 are generated below.
rng = random.Random(2026)

# --------------------------------------------------------------------------- users
# (user_id, name, role, employment_status, account_status, allowed_classes, can_view_student_records)
ALL = ["Grade 4", "Grade 5", "Grade 6", "Grade 7", "Grade 8"]
USERS = [
    # --- synthetic school-district staff ---
    ("U001", "Alex Carter", "Teacher", "Active", "Active", ["Grade 5"], True),
    ("U002", "Jordan Lee", "Teacher", "Inactive", "Active", ["Grade 5"], True),  # left, account still on
    ("U003", "Sam Wilson", "Principal", "Active", "Active", ["Grade 5", "Grade 6", "Grade 7"], True),
    # --- leadership / support staff ---
    ("U004", "Maria Gonzalez", "Vice Principal", "Active", "Active", ALL, True),
    ("U005", "Grace Liu", "Counselor", "Active", "Active", ALL, True),
    ("U006", "Omar Haddad", "Counselor", "Active", "Active", ["Grade 6", "Grade 7", "Grade 8"], True),
    ("U007", "Fatima Noor", "Registrar", "Active", "Active", ALL, True),
    ("U008", "Daniel Brooks", "Registrar", "Active", "Active", ALL, True),
    ("U009", "Kevin Zhao", "IT Admin", "Active", "Active", [], False),  # manages systems, not records
    ("U010", "Leila Rahimi", "IT Admin", "Active", "Active", [], False),
    # --- teachers ---
    ("U011", "Priya Nair", "Teacher", "Inactive", "Active", ["Grade 6", "Grade 7"], True),  # left, account still on
    ("U012", "Tom Hughes", "Teacher", "Active", "Active", ["Grade 7", "Grade 8"], True),
    ("U013", "Dana Okafor", "Teacher", "Active", "Active", ["Grade 5"], True),
    ("U014", "Hana Kim", "Teacher", "Active", "Active", ["Grade 6"], True),
    ("U015", "Noah Becker", "Teacher", "Active", "Active", ["Grade 4"], True),
    ("U016", "Marcus Bell", "Teacher", "Active", "Suspended", ["Grade 8"], True),  # account suspended
    ("U017", "Elena Rossi", "Teacher", "Inactive", "Disabled", ["Grade 4"], False),  # correctly off-boarded
    ("U018", "Aisha Khan", "Teacher", "Active", "Active", ["Grade 4", "Grade 5"], True),
    ("U019", "Lucas Meyer", "Teacher", "Active", "Active", ["Grade 6"], True),
    ("U020", "Sofia Petrova", "Teacher", "Active", "Active", ["Grade 7"], True),
    ("U021", "James O'Connor", "Teacher", "Active", "Active", ["Grade 8"], True),
    ("U022", "Mei Tanaka", "Teacher", "Active", "Active", ["Grade 4"], True),
    ("U023", "Carlos Mendes", "Teacher", "Active", "Active", ["Grade 5", "Grade 6"], True),
    ("U024", "Amara Diallo", "Teacher", "Active", "Active", ["Grade 7", "Grade 8"], True),
    ("U025", "Ethan Walker", "Teacher", "Active", "Active", ["Grade 8"], True),
    ("U026", "Zoe Fischer", "Teacher", "Active", "Active", ["Grade 6", "Grade 7"], True),
    # --- temporary / external ---
    ("U027", "Ben Archer", "Substitute", "Active", "Active", ["Grade 5"], True),
    ("U028", "Nadia Farouk", "Substitute", "Active", "Active", ["Grade 8"], True),
    ("U029", "Ravi Patel", "Contractor", "Active", "Active", [], False),  # no student-record access at all
    ("U030", "Hannah Schultz", "Contractor", "Active", "Active", [], False),
]

# --------------------------------------------------------------------------- students
FIRST = ["Liam", "Olivia", "Noah", "Emma", "Ava", "Elijah", "Sophia", "Lucas", "Mia", "Mason", "Isla", "Ethan",
         "Amelia", "Logan", "Harper", "Aiden", "Zara", "Yusuf", "Layla", "Ibrahim", "Anaya", "Mateo", "Chloe",
         "Arjun", "Nora", "Omar", "Ruby", "Kai", "Sana", "Leo", "Hiro", "Maya", "Diego", "Ella", "Tariq",
         "Freya", "Jonas", "Amina", "Felix", "Priya"]
LAST = ["Anderson", "Baker", "Chen", "Davis", "Evans", "Foster", "Garcia", "Hassan", "Ivanov", "Johnson",
        "Kowalski", "Lopez", "Martin", "Nguyen", "Owens", "Patel", "Quinn", "Reyes", "Singh", "Turner",
        "Usman", "Vargas", "Wright", "Xu", "Young", "Zimmerman", "Ahmed", "Bennett", "Costa", "Dubois"]
PER_CLASS = 24
# The five starter students keep their ID and class so existing references still work.
STARTER = {"S001": "Grade 5", "S002": "Grade 5", "S003": "Grade 6", "S004": "Grade 6", "S005": "Grade 7"}


def make_students():
    names = [f"{f} {l}" for f in FIRST for l in LAST]
    rng.shuffle(names)
    classes = ["Grade 4"] * PER_CLASS + ["Grade 5"] * PER_CLASS + ["Grade 6"] * PER_CLASS \
        + ["Grade 7"] * PER_CLASS + ["Grade 8"] * PER_CLASS
    # reserve starter slots first, then fill the rest in class order
    remaining = list(classes)
    for c in STARTER.values():
        remaining.remove(c)
    rest = sorted(remaining, key=lambda c: int(c.split()[1]))
    students, i = [], 0
    for n in range(1, len(classes) + 1):
        sid = f"S{n:03d}"
        cls = STARTER.get(sid)
        if cls is None:
            cls = rest.pop(0)
        students.append({"student_id": sid, "name": names[i], "class": cls, "district_id": "Central District"})
        i += 1
    return students


# --------------------------------------------------------------------------- logs
WEEKDAYS = [date(2026, 10, d) for d in (5, 6, 7, 8, 9, 12, 13)]  # Oct 10-11 are the weekend
# Users who only appear in seeded incidents get no "normal" traffic on top.
NO_NORMAL = {"U002", "U011", "U016", "U017", "U018", "U029", "U030", "U009", "U010"}


def ts(d, hh, mm):
    return datetime(d.year, d.month, d.day, hh, mm)


def normal_logs(users, students):
    by_class = {}
    for s in students:
        by_class.setdefault(s["class"], []).append(s["student_id"])
    out = []
    for u in users:
        uid, _, role, emp, acct, classes, can_view = u
        if uid in NO_NORMAL or emp != "Active" or acct != "Active" or not can_view:
            continue
        pool = [sid for c in classes for sid in by_class[c]]
        for d in WEEKDAYS:
            if rng.random() < 0.25:
                continue  # not everyone touches records every day
            for _ in range(rng.choice([1, 1, 2, 2, 3])):
                if role in ("Counselor", "Registrar", "Vice Principal"):
                    action = rng.choices(["view_record", "export_record", "edit_record"], [70, 15, 15])[0]
                elif role == "Principal":
                    action = "view_record"
                else:
                    action = rng.choices(["view_record", "edit_record"], [85, 15])[0]
                hh, mm = rng.randint(8, 15), rng.randint(0, 59)
                out.append({"user_id": uid, "student_id": rng.choice(pool), "action": action,
                            "when": ts(d, hh, mm), "result": "success", "tag": None})
    return out


def seeded_logs(students):
    """Generate the four non-starter incidents required by the official MVP scope."""
    cls = {}
    for s in students:
        cls.setdefault(s["class"], []).append(s["student_id"])
    logs, incidents = [], []

    def log(uid, sid, action, when, result="success", tag=None):
        logs.append({"user_id": uid, "student_id": sid, "action": action, "when": when,
                     "result": result, "tag": tag})

    def incident(n, title, uid, tag, risk, rec):
        incidents.append({"incident_id": f"I{n:03d}", "title": title, "user_id": uid, "tag": tag,
                          "expected_risk": risk, "expected_recommendation": rec})

    d = date(2026, 10, 13)

    # I002 — a teacher has been granted administrator-level permissions.
    log("U018", cls["Grade 4"][0], "view_record", ts(d, 9, 5), tag="I002")
    incident(2, "Teacher assigned excessive administrator-level permissions", "U018", "I002", "High",
             "Review the permission change, remove unnecessary privileges and restore least-privilege access.")

    # I003 — a teacher successfully accesses a student outside their assigned class.
    log("U001", cls["Grade 6"][0], "view_record", ts(d, 9, 10), tag="I003")
    incident(3, "Teacher accessed a student outside their assigned class", "U001", "I003", "High",
             "Investigate the access, verify whether an authorized exception exists and restrict access if needed.")

    # I004 — 100 record exports within ten minutes, representing bulk data access.
    targets = (cls["Grade 7"] + cls["Grade 8"])
    for k in range(100):
        minute = k // 10
        log("U012", targets[k % len(targets)], "export_record", ts(d, 10, minute),
            tag="I004" if k == 99 else None)
    incident(4, "Bulk download of student records in a short period", "U012", "I004", "High",
             "Review the activity, verify the user's identity and business purpose, and investigate possible data exposure.")

    # I005 — vendor attempts to cross the authorized district/tenant boundary.
    log("U029", "S001", "view_record", ts(d, 11, 5), tag="I005")
    incident(5, "Vendor accessed student records outside its approved district", "U029", "I005", "Critical",
             "Block unauthorized access, review vendor permissions, revoke compromised credentials if indicated, and investigate exposure.")

    return logs, incidents


def main():
    students = make_students()
    users = [{"user_id": u[0], "name": u[1], "role": u[2], "employment_status": u[3], "account_status": u[4]}
             for u in USERS]
    perms = []
    for u in USERS:
        uid, _, role, _, _, classes, can_view = u
        level = "Administrator" if uid == "U018" else ("Administrator" if role == "IT Admin" else "Standard")
        districts = ["North District"] if role == "Contractor" else ["Central District"]
        perms.append({"user_id": uid, "allowed_classes": classes, "can_view_student_records": can_view,
                      "permission_level": level, "authorized_districts": districts})

    original = [
        ("L001", "U001", "S001", "view_record", "2026-10-11 09:00", "success"),
        ("L002", "U002", "S002", "view_record", "2026-10-11 09:15", "success"),
        ("L003", "U001", "S001", "view_record", "2026-10-11 10:00", "success"),
        ("L004", "U003", "S004", "view_record", "2026-10-11 10:10", "success"),
        ("L005", "U001", "S004", "view_record", "2026-10-11 10:20", "denied"),
    ]
    logs = [{"log_id": a, "user_id": b, "student_id": c, "action": d, "timestamp": e, "result": f}
            for a, b, c, d, e, f in original]

    new = normal_logs(USERS, students)
    seeded, inc_new = seeded_logs(students)
    new += seeded
    new.sort(key=lambda r: (r["when"], r["user_id"]))
    tag_to_id = {}
    for n, r in enumerate(new, start=len(original) + 1):
        lid = f"L{n:03d}"
        if r["tag"]:
            tag_to_id[r["tag"]] = lid
        logs.append({"log_id": lid, "user_id": r["user_id"], "student_id": r["student_id"], "action": r["action"],
                     "timestamp": r["when"].strftime("%Y-%m-%d %H:%M"), "result": r["result"]})

    incidents = [
        {"incident_id": "I001", "title": "Former employee accessed student data", "user_id": "U002",
         "related_log_id": "L002", "expected_risk": "Critical",
         "expected_recommendation": "Disable the account, revoke active sessions, investigate recent activity, and verify offboarding."},
    ]
    for i in inc_new:
        incidents.append({"incident_id": i["incident_id"], "title": i["title"], "user_id": i["user_id"],
                          "related_log_id": tag_to_id[i["tag"]], "expected_risk": i["expected_risk"],
                          "expected_recommendation": i["expected_recommendation"]})

    for name, rows in (("users", users), ("permissions", perms), ("students", students),
                       ("access_logs", logs), ("incidents", incidents)):
        (DATA / f"{name}.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"{name}.json: {len(rows)} records")


if __name__ == "__main__":
    main()
