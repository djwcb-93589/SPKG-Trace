from __future__ import annotations

from .apache_access import ApacheAccessExtractor
from .apache_error import ApacheErrorExtractor
from .audit import AuditExtractor
from .auth import AuthExtractor
from .base import FamilyExtractor
from .dns import DnsExtractor
from .vpn import VpnExtractor


_EXTRACTORS: dict[str, FamilyExtractor] = {
    "dns": DnsExtractor(),
    "audit": AuditExtractor(),
    "auth": AuthExtractor(),
    "apache_access": ApacheAccessExtractor(),
    "apache_error": ApacheErrorExtractor(),
    "vpn": VpnExtractor(),
}

_ALIASES = {
    "dnsmasq": "dns",
    "inet_firewall_dns": "dns",
    "internal_share_audit": "audit",
    "intranet_server_audit": "audit",
    "apache": "apache_access",
    "apache2_access": "apache_access",
    "apache2_error": "apache_error",
    "openvpn": "vpn",
}


def get_family_extractor(family: str) -> FamilyExtractor:
    normalized = family.strip().lower().replace("-", "_")
    normalized = _ALIASES.get(normalized, normalized)
    try:
        return _EXTRACTORS[normalized]
    except KeyError as exc:
        supported = ", ".join(sorted(_EXTRACTORS))
        raise ValueError(
            f"Unsupported extraction family {family!r}; supported: {supported}"
        ) from exc
