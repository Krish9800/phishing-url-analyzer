"""Domain models representing parsed and analyzed URL structural metadata."""

from pydantic import BaseModel, Field


class ParsedURL(BaseModel):
    """Deconstructed structural metadata of an inspected URL."""

    raw_url: str = Field(description="Original unparsed URL input")
    refanged_url: str = Field(description="Cleaned, refanged URL for analysis")
    scheme: str = Field(default="", description="Protocol scheme (http, https, ftp, etc.)")
    netloc: str = Field(default="", description="Network authority location (host:port)")
    hostname: str = Field(default="", description="Extracted host (domain name or IP address)")
    port: int | None = Field(default=None, description="Explicit network port number if specified")
    path: str = Field(default="", description="URL resource path")
    query: str = Field(default="", description="Query string parameters")
    fragment: str = Field(default="", description="URL fragment anchor")
    tld: str = Field(default="", description="Top-level domain extension (e.g. com, org, ru)")
    registered_domain: str = Field(default="", description="Primary domain name with TLD")
    subdomains: list[str] = Field(default_factory=list, description="Subdomain labels")
    subdomain_depth: int = Field(default=0, description="Count of subdomain levels")
    has_ip_host: bool = Field(default=False, description="True if host is an IP address")
    is_punycode: bool = Field(default=False, description="True if domain contains xn-- prefix")
    decoded_punycode: str | None = Field(default=None, description="Unicode domain representation")
    domain_entropy: float = Field(default=0.0, description="Shannon entropy of the domain name")
    path_entropy: float = Field(default=0.0, description="Shannon entropy of the URL path")
