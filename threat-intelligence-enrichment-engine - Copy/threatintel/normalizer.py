"""Indicator parsing and normalization; does not contact remote systems."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit, urlunsplit


HASH_PATTERNS = {
    32: "MD5",
    40: "SHA1",
    64: "SHA256",
}
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


class IndicatorError(ValueError):
    """Raised when a supplied value cannot be recognized as a supported IOC."""


@dataclass(frozen=True)
class Indicator:
    original: str
    normalized: str
    ioc_type: str
    is_public_ip: bool = False
    is_global_ip: bool = False
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["notes"] = list(self.notes)
        return data


def defang(value: str) -> str:
    """Convert common analyst defanging formats to lookup-ready strings."""
    result = value.strip()
    result = re.sub(r"^hxxps(?=://)", "https", result, flags=re.IGNORECASE)
    result = re.sub(r"^hxxp(?=://)", "http", result, flags=re.IGNORECASE)
    result = re.sub(r"\s*\[\.\]\s*", ".", result)
    result = re.sub(r"\s*\(\.\)\s*", ".", result)
    result = re.sub(r"\s*\[:\]\s*", ":", result)
    return result.strip()


def _normalize_domain(domain: str) -> str:
    domain = domain.strip().rstrip(".").lower()
    if not domain:
        raise IndicatorError("Domain is empty.")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise IndicatorError("Domain contains invalid international characters.") from exc

    if len(domain) > 253:
        raise IndicatorError("Domain is longer than 253 characters.")
    labels = domain.split(".")
    if len(labels) < 2:
        raise IndicatorError("Enter a fully qualified domain, such as example.com.")
    if any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise IndicatorError("Domain format is invalid.")
    return domain


def normalize_ioc(raw: str) -> Indicator:
    """Identify and normalize an IP, domain, URL, or MD5/SHA1/SHA256 hash."""
    if not isinstance(raw, str) or not raw.strip():
        raise IndicatorError("Enter an indicator first.")
    original = raw.strip()
    value = defang(original)

    if any(char in value for char in "\r\n\x00"):
        raise IndicatorError("An indicator must be on one line.")

    # Hashes are unambiguous and should be detected before domain/URL parsing.
    if value.isascii() and value.isalnum() and len(value) in HASH_PATTERNS:
        if re.fullmatch(r"[A-Fa-f0-9]+", value):
            return Indicator(original, value.lower(), HASH_PATTERNS[len(value)])

    # IP literal.
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
        global_ip = ip.is_global
        notes = () if global_ip else ("This address is not globally routable; external reputation lookups are skipped.",)
        return Indicator(original, ip.compressed, "IPv4" if ip.version == 4 else "IPv6", global_ip, global_ip, notes)
    except ValueError:
        pass

    # A value with a URL scheme, path, query, fragment, or www prefix is treated as a URL.
    looks_like_url = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value)) or value.startswith("www.") or any(ch in value for ch in "/?#")
    if looks_like_url:
        candidate = value if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value) else "http://" + value
        try:
            parts = urlsplit(candidate)
            hostname = parts.hostname
            # Accessing .port detects malformed port syntax.
            _ = parts.port
        except ValueError as exc:
            raise IndicatorError(f"URL format is invalid: {exc}") from exc
        if parts.scheme.lower() not in {"http", "https"}:
            raise IndicatorError("Only HTTP and HTTPS URLs are supported.")
        if not hostname:
            raise IndicatorError("URL must contain a hostname.")

        try:
            host_ip = ipaddress.ip_address(hostname)
            normalized_host = f"[{host_ip.compressed}]" if host_ip.version == 6 else host_ip.compressed
        except ValueError:
            normalized_host = _normalize_domain(hostname)

        # Keep credentials in the normalized value so a heuristic can flag them, but never fetch the URL.
        userinfo = ""
        if parts.username is not None:
            userinfo = parts.username
            if parts.password is not None:
                userinfo += ":" + parts.password
            userinfo += "@"
        host_port = normalized_host
        if parts.port is not None:
            host_port += f":{parts.port}"
        netloc = userinfo + host_port
        normalized = urlunsplit((parts.scheme.lower(), netloc, parts.path or "", parts.query, parts.fragment))
        return Indicator(original, normalized, "URL")

    normalized_domain = _normalize_domain(value)
    return Indicator(original, normalized_domain, "Domain")
