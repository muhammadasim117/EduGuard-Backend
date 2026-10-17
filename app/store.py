"""Step 2: read the JSON files, validate them, and keep them in memory."""
import json
import os
from pathlib import Path

from .models import AccessLog, Incident, Permission, Student, User

DATA_DIR = Path(os.environ.get("DATA_DIR", Path(__file__).resolve().parent.parent / "data"))

FILES = {
    "users": ("users.json", User),
    "permissions": ("permissions.json", Permission),
    "students": ("students.json", Student),
    "access_logs": ("access_logs.json", AccessLog),
    "incidents": ("incidents.json", Incident),
}


class DataStore:
    def __init__(self) -> None:
        self.users: list[User] = []
        self.permissions: list[Permission] = []
        self.students: list[Student] = []
        self.access_logs: list[AccessLog] = []
        self.incidents: list[Incident] = []
        self.load()

    def load(self) -> None:
        """Load all files. Any problem raises a clear error naming file and record."""
        loaded = {}
        for attr, (filename, model) in FILES.items():
            path = DATA_DIR / filename
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                raise RuntimeError(f"Missing data file: {path}")
            except json.JSONDecodeError as e:
                raise RuntimeError(f"{filename} is not valid JSON: {e}")
            if not isinstance(raw, list):
                raise RuntimeError(f"{filename} must contain a JSON list of records")
            items = []
            for i, rec in enumerate(raw):
                try:
                    items.append(model.model_validate(rec))
                except Exception as e:
                    raise RuntimeError(f"{filename} record #{i + 1} is invalid: {e}")
            loaded[attr] = items
        # Only swap in the new data once everything loaded, so a bad reload keeps the old data.
        for attr, items in loaded.items():
            setattr(self, attr, items)

    def counts(self) -> dict[str, int]:
        return {k: len(getattr(self, k)) for k in FILES}

    def integrity_issues(self) -> list[str]:
        """Cross-file checks: every ID used in one file must exist in the file it points to."""
        user_ids = {u.user_id for u in self.users}
        student_ids = {s.student_id for s in self.students}
        log_ids = {l.log_id for l in self.access_logs}
        issues = []
        for p in self.permissions:
            if p.user_id not in user_ids:
                issues.append(f"permissions: unknown user_id {p.user_id}")
        for l in self.access_logs:
            if l.user_id not in user_ids:
                issues.append(f"access_logs {l.log_id}: unknown user_id {l.user_id}")
            if l.student_id not in student_ids:
                issues.append(f"access_logs {l.log_id}: unknown student_id {l.student_id}")
        for i in self.incidents:
            if i.user_id not in user_ids:
                issues.append(f"incidents {i.incident_id}: unknown user_id {i.user_id}")
            if i.related_log_id not in log_ids:
                issues.append(f"incidents {i.incident_id}: unknown related_log_id {i.related_log_id}")
        for kind, items, key in (("users", self.users, "user_id"), ("students", self.students, "student_id"),
                                 ("access_logs", self.access_logs, "log_id"), ("incidents", self.incidents, "incident_id")):
            ids = [getattr(x, key) for x in items]
            for d in {x for x in ids if ids.count(x) > 1}:
                issues.append(f"{kind}: duplicate {key} {d}")
        return issues


store = DataStore()
