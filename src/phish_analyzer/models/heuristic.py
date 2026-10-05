"""Heuristic trigger and severity models for threat scoring."""

from enum import StrEnum

from pydantic import BaseModel, Field


class HeuristicSeverity(StrEnum):
    """Severity classification for individual heuristic detections."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class HeuristicTrigger(BaseModel):
    """Specific detection rule triggered during URL threat inspection."""

    rule_id: str = Field(description="Unique identifier for the heuristic rule")
    name: str = Field(description="Human-readable rule name")
    severity: HeuristicSeverity = Field(description="Severity classification")
    score_weight: int = Field(ge=0, le=50, description="Point contribution to score")
    description: str = Field(description="Detailed explanation of the detected threat pattern")
    evidence: str = Field(description="Specific string or component value that triggered the rule")
