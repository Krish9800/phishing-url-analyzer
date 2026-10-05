"""Threat report and risk evaluation domain models."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from phish_analyzer.models.heuristic import HeuristicTrigger
from phish_analyzer.models.url_record import ParsedURL


class RiskLevel(StrEnum):
    """Overall classification of evaluated URL threat."""

    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class ThreatReport(BaseModel):
    """Consolidated threat analysis report containing indicators, scoring, and telemetry."""

    raw_url: str = Field(description="Original input URL evaluated.")
    defanged_url: str = Field(description="Safely defanged URL preventing accidental navigation.")
    threat_score: int = Field(
        ge=0, le=100, description="Composite threat score normalized from 0 to 100."
    )
    risk_level: RiskLevel = Field(description="Categorical risk classification.")
    parsed_url: ParsedURL = Field(description="Extracted lexical and structural components.")
    triggers: list[HeuristicTrigger] = Field(
        default_factory=list, description="Security rules triggered during evaluation."
    )
    recommendations: list[str] = Field(
        default_factory=list, description="Prescriptive defensive countermeasure recommendations."
    )
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of the threat evaluation.",
    )

    def to_cef(self) -> str:
        """Export analysis finding to ArcSight Common Event Format (CEF) for SIEM ingestion."""
        severity_map = {
            RiskLevel.BENIGN: 1,
            RiskLevel.SUSPICIOUS: 6,
            RiskLevel.MALICIOUS: 9,
        }
        num_severity = severity_map.get(self.risk_level, 5)
        top_rule = self.triggers[0].rule_id if self.triggers else "NO_THREAT_DETECTED"
        top_name = self.triggers[0].name if self.triggers else "Clean URL Analysis"

        # Sanitize pipe and equals characters in CEF extension
        safe_url = self.defanged_url.replace("|", "%7C").replace("=", "%3D")
        ext = (
            f"request={safe_url} "
            f"cs1={self.risk_level.value} cs1Label=RiskLevel "
            f"cn1={self.threat_score} cn1Label=ThreatScore "
            f"cn2={len(self.triggers)} cn2Label=TriggerCount"
        )

        return (
            f"CEF:0|DefensiveSecurity|PhishAnalyzer|0.1.0|"
            f"{top_rule}|{top_name}|{num_severity}|{ext}"
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert model to JSON-serializable dictionary."""
        return self.model_dump(mode="json")
