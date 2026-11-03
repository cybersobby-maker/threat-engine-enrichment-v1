"""Orchestrates normalization, local analysis, optional lookups, scoring, and persistence."""
from __future__ import annotations

import os
from dotenv import load_dotenv

from .normalizer import IndicatorError, normalize_ioc
from .providers import lookup_abuseipdb, lookup_virustotal
from .scoring import local_analysis, score_indicator
from .storage import save_result

load_dotenv()


def configured_keys() -> dict[str, str]:
    return {
        "virustotal": os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
        "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", "").strip(),
    }


def enrich_indicator(raw: str, allow_external: bool = False, api_keys: dict[str, str] | None = None) -> dict:
    indicator = normalize_ioc(raw)
    normalized = indicator.to_dict()
    local = local_analysis(normalized)
    keys = api_keys if api_keys is not None else configured_keys()
    sources: dict[str, dict] = {}

    if allow_external:
        # Never send private/reserved IP addresses to public reputation providers.
        should_query_vt = indicator.ioc_type not in {"IPv4", "IPv6"} or indicator.is_public_ip
        if should_query_vt:
            sources["VirusTotal"] = lookup_virustotal(normalized, keys.get("virustotal", ""))
        else:
            sources["VirusTotal"] = {"status": "skipped", "message": "Non-global IP; external lookup was skipped."}
        sources["AbuseIPDB"] = lookup_abuseipdb(normalized, keys.get("abuseipdb", ""))
    else:
        sources["VirusTotal"] = {"status": "disabled", "message": "External lookups are disabled for this run."}
        sources["AbuseIPDB"] = {"status": "disabled", "message": "External lookups are disabled for this run."}

    scored = score_indicator(normalized, local, sources)
    result = {
        "indicator": indicator.original,
        "normalized": indicator.normalized,
        "ioc_type": indicator.ioc_type,
        "is_public_ip": indicator.is_public_ip,
        "risk_score": scored["risk_score"],
        "verdict": scored["verdict"],
        "summary": scored["summary"],
        "evidence": scored["evidence"],
        "sources": sources,
        "local_analysis": local,
    }
    return result


def enrich_and_save(raw: str, allow_external: bool = False, api_keys: dict[str, str] | None = None, db_path=None) -> dict:
    result = enrich_indicator(raw, allow_external=allow_external, api_keys=api_keys)
    save_result(result, db_path=db_path)
    return result


__all__ = ["IndicatorError", "configured_keys", "enrich_indicator", "enrich_and_save"]
