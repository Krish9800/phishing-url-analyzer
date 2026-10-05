"""Pydantic request and response schemas for REST API endpoints."""

from typing import Annotated

from pydantic import BaseModel, Field

from phish_analyzer.models.report import RiskLevel, ThreatReport


class AnalyzeRequest(BaseModel):
    """Payload for single URL threat evaluation."""

    url: Annotated[
        str, Field(min_length=1, max_length=4096, description="Target URL string to evaluate")
    ]


class BatchAnalyzeRequest(BaseModel):
    """Payload for bulk URL threat evaluation with DoS guard limits."""

    urls: Annotated[
        list[str],
        Field(
            min_length=1,
            max_length=200,
            description="List of URL strings to analyze concurrently (max 200).",
        ),
    ]


class BatchAnalyzeResponse(BaseModel):
    """Aggregate response for bulk URL evaluations."""

    total: int = Field(description="Total count of URLs evaluated")
    summary: dict[RiskLevel, int] = Field(description="Counts breakdown by risk category")
    reports: list[ThreatReport] = Field(description="List of detailed threat reports")


class DefangRequest(BaseModel):
    """Request payload to safely defang or refang a URL."""

    url: str = Field(description="URL to defang")


class DefangResponse(BaseModel):
    """Defanged URL representation."""

    raw_url: str = Field(description="Original input URL")
    defanged_url: str = Field(description="Safely neutralized URL")


class HealthResponse(BaseModel):
    """API health status and service metadata."""

    status: str = Field(default="healthy", description="Service operating status")
    version: str = Field(description="Analyzer engine semantic version")
    service: str = Field(description="Service application name")
