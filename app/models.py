"""Data models. Field names match the partner's JSON files exactly (no renaming),
so the API output looks the same as the files and their security script."""
from pydantic import BaseModel, ConfigDict, Field


class User(BaseModel):
    user_id: str
    name: str
    role: str
    employment_status: str  # "Active" / "Inactive"
    account_status: str  # "Active" / ...


class Permission(BaseModel):
    user_id: str
    allowed_classes: list[str]
    can_view_student_records: bool
    # Explicit privilege level makes excessive permissions detectable.
    permission_level: str = "Standard"
    # Vendor access is limited to named district/tenant boundaries.
    authorized_districts: list[str] = Field(default_factory=lambda: ["Central District"])


class Student(BaseModel):
    student_id: str
    name: str
    # JSON key is "class"; stored as class_ in Python (class is a reserved word)
    class_: str = Field(alias="class")
    district_id: str = "Central District"

    model_config = ConfigDict(populate_by_name=True)


class AccessLog(BaseModel):
    log_id: str
    user_id: str
    student_id: str
    action: str
    timestamp: str  # "YYYY-MM-DD HH:MM"
    result: str  # "success" / "denied"


class Incident(BaseModel):
    incident_id: str
    title: str
    user_id: str
    related_log_id: str
    expected_risk: str
    expected_recommendation: str
