from enum import StrEnum

from pydantic import BaseModel, field_validator


class ScanStatus(StrEnum):
    queued = "queued"
    running = "running"
    complete = "complete"
    failed = "failed"
    rejected = "rejected"


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target_url: str
    owns_target: bool
    include_third_party: bool = False

    @field_validator("owns_target")
    @classmethod
    def must_attest_ownership(cls, v: bool) -> bool:
        if not v:
            raise ValueError("owns_target must be true to initiate a scan")
        return v


class ScanInitResponse(BaseModel):
    scan_id: str
    status: ScanStatus


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    allow_private_targets: bool


# ---------------------------------------------------------------------------
# Finding sub-models (populated in later phases)
# ---------------------------------------------------------------------------


class Evidence(BaseModel):
    location: str
    line: int | None = None
    redacted_value: str | None = None
    context: str | None = None


class AttackEntry(BaseModel):
    id: str
    name: str
    what_it_is: str
    how_it_applies_here: str
    impact: str


class Reference(BaseModel):
    label: str
    url: str


class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    evidence: Evidence
    why_it_matters: str
    attacks: list[AttackEntry]
    remediation: list[str]
    references: list[Reference]


# ---------------------------------------------------------------------------
# Summary and full scan report
# ---------------------------------------------------------------------------


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanSummary(BaseModel):
    score: int
    grade: str
    counts: SeverityCounts
    headline: str


class ScanReport(BaseModel):
    scan_id: str
    status: ScanStatus
    target_url: str
    started_at: str
    duration_seconds: float | None = None
    summary: ScanSummary | None = None
    findings: list[Finding] = []
    not_checked: list[str] = []
    pages_crawled: int = 0
    assets_scanned: int = 0


class RejectionResponse(BaseModel):
    status: ScanStatus = ScanStatus.rejected
    reason: str
    message: str
