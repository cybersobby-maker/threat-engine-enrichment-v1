from threatintel.engine import enrich_indicator
from threatintel.storage import get_recent


def test_local_mode_does_not_enable_external_lookup():
    result = enrich_indicator("192.0.2.10", allow_external=False)
    assert result["sources"]["VirusTotal"]["status"] == "disabled"
    assert result["sources"]["AbuseIPDB"]["status"] == "disabled"


def test_non_global_ip_skips_external_lookups_when_enabled():
    result = enrich_indicator("192.0.2.10", allow_external=True, api_keys={"virustotal": "fake", "abuseipdb": "fake"})
    assert result["sources"]["VirusTotal"]["status"] == "skipped"
    assert result["sources"]["AbuseIPDB"]["status"] == "skipped"


def test_synthetic_domain_has_unknown_verdict_without_lookups():
    result = enrich_indicator("example.com", allow_external=False)
    assert result["verdict"] == "Unknown"
    assert "not proof" in result["summary"]
