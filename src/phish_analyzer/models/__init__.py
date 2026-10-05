"""Data models package for URL analysis."""

from phish_analyzer.models.heuristic import HeuristicSeverity, HeuristicTrigger
from phish_analyzer.models.report import RiskLevel, ThreatReport
from phish_analyzer.models.url_record import ParsedURL

__all__ = ["HeuristicSeverity", "HeuristicTrigger", "ParsedURL", "RiskLevel", "ThreatReport"]
