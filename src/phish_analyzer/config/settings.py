"""Configuration settings and detection thresholds for Phishing URL Analyzer."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings, heuristic thresholds, and target brand catalogs."""

    model_config = SettingsConfigDict(
        env_prefix="PHISH_",
        case_sensitive=False,
    )

    APP_NAME: str = "Phishing URL Analyzer"
    VERSION: str = "0.1.0"
    DEBUG: bool = False

    # Detection thresholds
    SHANNON_ENTROPY_THRESHOLD: float = Field(
        default=4.0,
        description="Threshold above which domain lexical entropy indicates DGA or random tokens.",
    )
    MAX_SUBDOMAIN_DEPTH: int = Field(
        default=3,
        description="Maximum expected subdomain depth before triggering subdomain stuffing alert.",
    )
    MAX_PATH_LENGTH: int = Field(
        default=80,
        description="Path length threshold for excessive URL length heuristic.",
    )
    TYPOSQUAT_MAX_DISTANCE: int = Field(
        default=1,
        description="Levenshtein distance threshold for brand impersonation detection.",
    )

    # Risk score boundaries (0 - 100)
    SUSPICIOUS_SCORE_THRESHOLD: int = 40
    MALICIOUS_SCORE_THRESHOLD: int = 70

    # High-value monitored brand targets (normalized lowercase names)
    TARGETED_BRANDS: list[str] = Field(
        default=[
            "paypal",
            "google",
            "microsoft",
            "apple",
            "amazon",
            "netflix",
            "facebook",
            "instagram",
            "chase",
            "wellsfargo",
            "bankofamerica",
            "binance",
            "coinbase",
            "github",
            "dropbox",
            "adobe",
            "dhl",
            "fedex",
            "usps",
            "whatsapp",
            "telegram",
            "outlook",
            "icloud",
        ]
    )

    # Keywords frequently abused in phishing lures
    SUSPICIOUS_KEYWORDS: list[str] = Field(
        default=[
            "login",
            "signin",
            "logon",
            "verify",
            "verification",
            "account",
            "banking",
            "security",
            "update",
            "secure",
            "wallet",
            "confirm",
            "password",
            "credential",
            "support",
            "billing",
            "invoice",
            "auth",
            "authenticate",
            "recover",
            "recovery",
            "suspended",
            "suspend",
            "unusual",
            "activity",
            "re-activate",
        ]
    )

    # TLDs historically correlated with high concentrations of malicious abuse
    HIGH_RISK_TLDS: list[str] = Field(
        default=[
            "tk",
            "ml",
            "ga",
            "cf",
            "gq",
            "top",
            "xyz",
            "icu",
            "work",
            "click",
            "live",
            "loan",
            "buzz",
            "fit",
            "rest",
            "surf",
            "cam",
            "cfd",
        ]
    )


settings = Settings()
