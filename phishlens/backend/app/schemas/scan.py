from __future__ import annotations

from pydantic import BaseModel, Field


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    privacy_mode: bool = Field(default=True, description="If true the scan is not saved to history.")


class EmailScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20000)
    headers: str = Field(default="", max_length=20000)
    privacy_mode: bool = True


class IndicatorOut(BaseModel):
    id: str
    title: str
    severity: str
    explanation: str
    evidence: str
    provenance: str
    reliability: float
    points: float
    counted: bool


class SourceOut(BaseModel):
    name: str
    status: str
    detail: str
    is_mock: bool


class AIOut(BaseModel):
    summary: str
    social_engineering_indicators: list[str]
    evidence_references: list[str]
    recommended_actions: list[str]
    limitations: list[str]
    source: str   # "ai" | "rules"


class ScanReport(BaseModel):
    scan_id: str
    kind: str                       # "url" | "email"
    created_at: str
    duration_ms: int
    target: str                     # normalized URL, or "email (not stored)"
    score: int
    verdict: str
    confidence: str
    indicators: list[IndicatorOut]
    sources: list[SourceOut]
    unknowns: list[str]
    notes: list[str]
    explanation: AIOut
    redirect_chain: list[str] = []
    limitations: str = (
        "PhishLens combines rule-based checks and available reputation sources. It can miss new or targeted "
        "threats. The score is an internal risk estimate, not a probability. Absence of a warning is not proof "
        "of safety."
    )
