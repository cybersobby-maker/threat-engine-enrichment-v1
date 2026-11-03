"""Read-only reputation lookups for VirusTotal and AbuseIPDB."""
from __future__ import annotations

import base64
from urllib.parse import quote

import requests

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT_SECONDS = 12


def _error_message(response: requests.Response) -> str:
    if response.status_code == 429:
        return "Provider rate limit reached. Wait before retrying."
    if response.status_code in {401, 403}:
        return "Provider rejected the API key or this endpoint is not enabled for the account."
    if response.status_code == 404:
        return "No report found for this indicator."
    return f"Provider returned HTTP {response.status_code}."


def lookup_virustotal(indicator: dict, api_key: str) -> dict:
    if not api_key:
        return {"status": "skipped", "message": "VIRUSTOTAL_API_KEY is not configured."}

    kind = indicator["ioc_type"]
    normalized = indicator["normalized"]
    if kind in {"IPv4", "IPv6"}:
        path = f"ip_addresses/{quote(normalized, safe=':')}"
    elif kind == "Domain":
        path = f"domains/{quote(normalized, safe='')}"
    elif kind == "URL":
        url_id = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii").rstrip("=")
        path = f"urls/{quote(url_id, safe='')}"
    elif kind in {"MD5", "SHA1", "SHA256"}:
        path = f"files/{quote(normalized, safe='')}"
    else:
        return {"status": "skipped", "message": f"Unsupported indicator type: {kind}"}

    try:
        response = requests.get(
            f"{VT_BASE}/{path}",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        return {"status": "error", "message": f"Network error: {type(exc).__name__}"}

    if response.status_code == 404:
        return {"status": "not_found", "message": "No existing VirusTotal report found."}
    if response.status_code != 200:
        return {"status": "error", "message": _error_message(response)}

    try:
        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {}) or {}
        return {
            "status": "ok",
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "reputation": attributes.get("reputation"),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }
    except (ValueError, TypeError, AttributeError):
        return {"status": "error", "message": "Provider response could not be parsed."}


def lookup_abuseipdb(indicator: dict, api_key: str) -> dict:
    if not api_key:
        return {"status": "skipped", "message": "ABUSEIPDB_API_KEY is not configured."}
    if indicator["ioc_type"] not in {"IPv4", "IPv6"}:
        return {"status": "skipped", "message": "AbuseIPDB checks IP addresses only."}
    if not indicator.get("is_public_ip", False):
        return {"status": "skipped", "message": "Non-global IP; external lookup was skipped."}

    try:
        response = requests.get(
            ABUSE_BASE,
            params={"ipAddress": indicator["normalized"], "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        return {"status": "error", "message": f"Network error: {type(exc).__name__}"}

    if response.status_code != 200:
        return {"status": "error", "message": _error_message(response)}
    try:
        data = response.json().get("data", {})
        return {
            "status": "ok",
            "ip_address": data.get("ipAddress"),
            "abuse_confidence_score": int(data.get("abuseConfidenceScore", 0) or 0),
            "total_reports": int(data.get("totalReports", 0) or 0),
            "num_distinct_users": int(data.get("numDistinctUsers", 0) or 0),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
        }
    except (ValueError, TypeError, AttributeError):
        return {"status": "error", "message": "Provider response could not be parsed."}
