"""Detects raw and obfuscated IP address representations in URL hostnames."""

import ipaddress
import re

from phish_analyzer.models.heuristic import HeuristicSeverity, HeuristicTrigger
from phish_analyzer.models.url_record import ParsedURL


class IPObfuscationDetector:
    """Identifies and decodes obfuscated IP formats used for filter evasion and SSRF."""

    @classmethod
    def detect(cls, parsed_url: ParsedURL) -> list[HeuristicTrigger]:
        """Inspect parsed URL hostname for raw or obfuscated IP representations.

        Args:
            parsed_url: Structured ParsedURL model.

        Returns:
            List of triggered security heuristics.
        """
        triggers: list[HeuristicTrigger] = []
        host = parsed_url.hostname.strip()
        if not host:
            return triggers

        decoded_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        is_obfuscated = False
        obfuscation_type = ""

        # 1. Check for Dword integer representation (e.g. 2130706433 or 0x7f000001)
        if re.match(r"^0x[0-9a-fA-F]{1,8}$", host):
            try:
                val = int(host, 16)
                decoded_ip = ipaddress.IPv4Address(val)
                is_obfuscated = True
                obfuscation_type = "Single Hexadecimal Dword"
            except (ValueError, ipaddress.AddressValueError):
                pass
        elif re.match(r"^[0-9]{8,11}$", host):
            try:
                val = int(host, 10)
                if val <= 4294967295:
                    decoded_ip = ipaddress.IPv4Address(val)
                    is_obfuscated = True
                    obfuscation_type = "Integer Dword"
            except (ValueError, ipaddress.AddressValueError):
                pass

        # 2. Check for dotted octal or dotted hex (e.g. 0177.0.0.1 or 0x7f.0.0.1)
        if decoded_ip is None and "." in host:
            parts = host.split(".")
            if len(parts) == 4:
                try:
                    octets = []
                    has_hex_or_octal = False
                    for p in parts:
                        if p.startswith("0x") or p.startswith("0X"):
                            octets.append(int(p, 16))
                            has_hex_or_octal = True
                        elif p.startswith("0") and len(p) > 1 and p.isdigit():
                            octets.append(int(p, 8))
                            has_hex_or_octal = True
                        elif p.isdigit():
                            octets.append(int(p, 10))
                        else:
                            break

                    if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
                        ip_str = ".".join(str(o) for o in octets)
                        decoded_ip = ipaddress.IPv4Address(ip_str)
                        if has_hex_or_octal:
                            is_obfuscated = True
                            obfuscation_type = "Dotted Hex/Octal"
                except (ValueError, ipaddress.AddressValueError):
                    pass

        # 3. Standard Dotted Decimal IPv4 or IPv6
        if decoded_ip is None:
            try:
                decoded_ip = ipaddress.ip_address(host)
            except ValueError:
                pass

        if decoded_ip is None:
            return triggers

        # Rule A: Obfuscated IP Notation
        if is_obfuscated:
            triggers.append(
                HeuristicTrigger(
                    rule_id="OBFUSCATED_IP_HOST",
                    name="Obfuscated IP Address Hostname",
                    severity=HeuristicSeverity.CRITICAL,
                    score_weight=35,
                    description=(
                        f"Hostname uses {obfuscation_type} notation to evade static URL and DNS "
                        f"filters. Resolves to IPv4: {decoded_ip}."
                    ),
                    evidence=f"raw='{host}' -> normalized='{decoded_ip}'",
                )
            )
        else:
            # Rule B: Plain raw IP address host
            triggers.append(
                HeuristicTrigger(
                    rule_id="RAW_IP_HOST",
                    name="Raw IP Address Host",
                    severity=HeuristicSeverity.HIGH,
                    score_weight=25,
                    description=(
                        "Target URL uses a raw IP address instead of a standard registered domain "
                        "name. Commonly used by malicious infrastructure to bypass domain checks."
                    ),
                    evidence=f"ip='{decoded_ip}'",
                )
            )

        # Rule C: Private / Reserved IP Range (SSRF / Internal Attack Risk)
        if decoded_ip.is_private or decoded_ip.is_loopback or decoded_ip.is_link_local:
            triggers.append(
                HeuristicTrigger(
                    rule_id="PRIVATE_IP_SSRF_RISK",
                    name="Private or Loopback IP Address (SSRF Risk)",
                    severity=HeuristicSeverity.CRITICAL,
                    score_weight=35,
                    description=(
                        "Target resolves to a private or loopback IP range (RFC 1918 / RFC 3927). "
                        "Indicates an SSRF or internal network exploit attempt."
                    ),
                    evidence=(
                        f"ip='{decoded_ip}', is_private={decoded_ip.is_private}, "
                        f"is_loopback={decoded_ip.is_loopback}"
                    ),
                )
            )

        return triggers
