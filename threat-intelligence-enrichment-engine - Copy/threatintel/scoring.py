"""Transparent risk scoring. Scores prioritize investigation; they are not proof."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "xyz", "work", "support", "country", "gq", "tk"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly"}
SUSPICIOUS_TERMS = {"login", "verify", "wallet", "password", "invoice", "account", "reset", "credential", "signin"}


def local_analysis(indicator: dict) -> dict:
    """Apply simple explainable heuristics without network access."""
    kind = indicator["ioc_type"]
    value = indicator["normalized"]
    score = 0
    evidence: list[str] = []

    if kind in {"IPv4", "IPv6"}:
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            evidence.append("IP is private, reserved, loopback, or otherwise non-global; no external lookup was attempted.")
        else:
            evidence.append("Public IP address; reputation sources can add context.")
        return {"score": 0, "evidence": evidence, "label": "Address classification only"}

    if kind == "Domain":
        domain = value
        labels = domain.split(".")
        tld = labels[-1]
        if tld in SUSPICIOUS_TLDS:
            score += 12
            evidence.append(f"Uses the higher-caution .{tld} TLD (weak signal; legitimate domains can use it).")
        if "xn--" in domain:
            score += 25
            evidence.append("Contains punycode, which can be used for visually deceptive domain names.")
        if domain.count("-") >= 3:
            score += 8
            evidence.append("Domain contains multiple hyphens (weak signal).")
        if any(term in domain for term in SUSPICIOUS_TERMS):
            score += 12
            evidence.append("Domain contains a credential/account-related term (weak signal).")

    if kind == "URL":
        parts = urlsplit(value)
        hostname = parts.hostname or ""
        host = hostname.lower()
        try:
            ipaddress.ip_address(host)
            score += 15
            evidence.append("URL uses an IP literal instead of a domain name.")
        except ValueError:
            pass
        if parts.username is not None or parts.password is not None:
            score += 30
            evidence.append("URL contains user-info before the hostname; check for deceptive URL construction.")
        if parts.scheme.lower() == "http":
            score += 4
            evidence.append("URL uses HTTP rather than HTTPS (weak signal; not inherently malicious).")
        if parts.port and parts.port not in {80, 443}:
            score += 8
            evidence.append(f"URL uses a non-standard port ({parts.port}).")
        if host in URL_SHORTENERS:
            score += 12
            evidence.append("URL uses a known URL-shortening service; destination is not expanded automatically.")
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            score += 12
            evidence.append(f"URL hostname uses the higher-caution .{tld} TLD (weak signal).")
        if "xn--" in host:
            score += 25
            evidence.append("URL hostname contains punycode.")
        searchable = (parts.path + "?" + parts.query).lower()
        matches = sorted(term for term in SUSPICIOUS_TERMS if term in searchable)
        if matches:
            score += min(20, 5 + 3 * len(matches))
            evidence.append("URL path/query contains account-related terms: " + ", ".join(matches) + ".")
        if len(parts.query) > 180:
            score += 5
            evidence.append("URL has a long query string (weak signal).")

    score = min(score, 45)  # Heuristics alone must never create a High/Critical result.
    if not evidence:
        evidence.append("No local heuristic flags were triggered. This is not proof the indicator is safe.")
    return {"score": score, "evidence": evidence, "label": "Local heuristics"}


def score_indicator(indicator: dict, local: dict, sources: dict) -> dict:
    """Combine provider signals with a conservative, explainable maximum-based score."""
    score = int(local.get("score", 0))
    evidence = list(local.get("evidence", []))

    vt = sources.get("VirusTotal", {})
    if vt.get("status") == "ok":
        malicious = int(vt.get("malicious", 0) or 0)
        suspicious = int(vt.get("suspicious", 0) or 0)
        if malicious:
            if malicious >= 8:
                vt_score = min(95, 75 + malicious)
            elif malicious >= 4:
                vt_score = 65
            elif malicious >= 2:
                vt_score = 45
            else:
                vt_score = 30
            score = max(score, vt_score)
            evidence.append(f"VirusTotal reported {malicious} malicious engine verdict(s).")
        if suspicious:
            suspicious_score = min(50, 20 + suspicious * 5)
            score = max(score, suspicious_score)
            evidence.append(f"VirusTotal reported {suspicious} suspicious engine verdict(s).")
        if not malicious and not suspicious:
            evidence.append("VirusTotal returned no malicious or suspicious engine verdicts; this does not prove the indicator is safe.")
        if vt.get("reputation") is not None and vt.get("reputation", 0) < 0:
            reputation_score = min(60, 20 + abs(int(vt["reputation"])) // 2)
            score = max(score, reputation_score)
            evidence.append(f"VirusTotal community reputation is negative ({vt['reputation']}).")
    elif vt.get("status") == "error":
        evidence.append("VirusTotal lookup failed: " + str(vt.get("message", "unknown error")))

    abuse = sources.get("AbuseIPDB", {})
    if abuse.get("status") == "ok":
        confidence = int(abuse.get("abuse_confidence_score", 0) or 0)
        if confidence > 0:
            score = max(score, min(95, confidence))
            evidence.append(f"AbuseIPDB abuse confidence score: {confidence}/100.")
        else:
            evidence.append("AbuseIPDB returned an abuse confidence score of 0/100 for its requested reporting window.")
    elif abuse.get("status") == "error":
        evidence.append("AbuseIPDB lookup failed: " + str(abuse.get("message", "unknown error")))

    # Reward corroboration, not duplicate signals from the same provider.
    supporting_providers = 0
    if vt.get("status") == "ok" and (vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0):
        supporting_providers += 1
    if abuse.get("status") == "ok" and abuse.get("abuse_confidence_score", 0) > 0:
        supporting_providers += 1
    if supporting_providers >= 2:
        score = min(100, score + 5)
        evidence.append("Independent external providers both returned a positive abuse signal (+5 corroboration adjustment).")

    score = max(0, min(100, int(score)))
    if score >= 75:
        verdict = "Critical"
    elif score >= 50:
        verdict = "High"
    elif score >= 25:
        verdict = "Medium"
    elif score > 0:
        verdict = "Low"
    else:
        verdict = "Unknown"

    if not any(s.get("status") == "ok" for s in sources.values()) and score == 0:
        summary = "No external reputation verdict available; local checks found no strong heuristic signals. This is not proof the indicator is safe."
    elif score == 0:
        summary = "No positive risk signals found in the available results; not a guarantee of safety."
    else:
        summary = f"{verdict} investigation priority based on a risk score of {score}/100. Validate the evidence before taking action."

    return {"risk_score": score, "verdict": verdict, "summary": summary, "evidence": evidence}
