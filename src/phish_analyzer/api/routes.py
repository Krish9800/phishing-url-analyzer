"""REST API endpoint routes for threat intelligence analysis."""

from fastapi import APIRouter, status

from phish_analyzer.api.schemas import (
    AnalyzeRequest,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    DefangRequest,
    DefangResponse,
    HealthResponse,
)
from phish_analyzer.config.settings import settings
from phish_analyzer.core.defanger import defang_url
from phish_analyzer.models.report import RiskLevel, ThreatReport
from phish_analyzer.scoring.engine import ScoringEngine

router = APIRouter(prefix="/api/v1", tags=["Analysis"])
health_router = APIRouter(tags=["Health"])


@health_router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
)
def get_health() -> HealthResponse:
    """Return runtime health status and version metadata."""
    return HealthResponse(
        status="healthy",
        version=settings.VERSION,
        service=settings.APP_NAME,
    )


@router.post(
    "/analyze",
    response_model=ThreatReport,
    status_code=status.HTTP_200_OK,
    summary="Analyze single URL for phishing indicators",
)
def analyze_url(payload: AnalyzeRequest) -> ThreatReport:
    """Perform comprehensive lexical, homoglyph, and obfuscation heuristics on a URL."""
    return ScoringEngine.analyze(payload.url)


@router.post(
    "/analyze/batch",
    response_model=BatchAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch analyze a list of URLs",
)
def analyze_batch(payload: BatchAnalyzeRequest) -> BatchAnalyzeResponse:
    """Evaluate up to 200 URLs in bulk and return aggregate threat distribution."""
    counts = {RiskLevel.BENIGN: 0, RiskLevel.SUSPICIOUS: 0, RiskLevel.MALICIOUS: 0}
    reports: list[ThreatReport] = []

    for url in payload.urls:
        report = ScoringEngine.analyze(url)
        reports.append(report)
        counts[report.risk_level] += 1

    return BatchAnalyzeResponse(
        total=len(reports),
        summary=counts,
        reports=reports,
    )


@router.post(
    "/defang",
    response_model=DefangResponse,
    status_code=status.HTTP_200_OK,
    summary="Defang a URL for safe sharing",
)
def defang_endpoint(payload: DefangRequest) -> DefangResponse:
    """Neutralize a potentially malicious URL preventing accidental client execution."""
    return DefangResponse(
        raw_url=payload.url,
        defanged_url=defang_url(payload.url),
    )
