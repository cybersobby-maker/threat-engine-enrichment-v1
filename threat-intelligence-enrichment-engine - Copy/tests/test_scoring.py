from threatintel.scoring import local_analysis, score_indicator


def test_local_heuristics_are_capped_below_high():
    indicator = {"ioc_type": "URL", "normalized": "http://user:password@192.0.2.4:8080/login?reset=password"}
    result = local_analysis(indicator)
    assert result["score"] <= 45
    assert any("user-info" in item for item in result["evidence"])


def test_virus_total_malicious_detection_raises_score():
    indicator = {"ioc_type": "Domain", "normalized": "example.com"}
    local = {"score": 0, "evidence": []}
    sources = {"VirusTotal": {"status": "ok", "malicious": 8, "suspicious": 0, "reputation": 0}}
    result = score_indicator(indicator, local, sources)
    assert result["risk_score"] >= 75
    assert result["verdict"] == "Critical"


def test_two_providers_add_corroboration():
    indicator = {"ioc_type": "IPv4", "normalized": "8.8.8.8"}
    local = {"score": 0, "evidence": []}
    sources = {
        "VirusTotal": {"status": "ok", "malicious": 2, "suspicious": 0, "reputation": 0},
        "AbuseIPDB": {"status": "ok", "abuse_confidence_score": 40},
    }
    result = score_indicator(indicator, local, sources)
    assert result["risk_score"] == 50
    assert result["verdict"] == "High"
    assert any("both returned" in item for item in result["evidence"])


def test_no_provider_data_does_not_claim_clean():
    indicator = {"ioc_type": "SHA256", "normalized": "0" * 64}
    local = {"score": 0, "evidence": ["No local heuristic flags."]}
    sources = {"VirusTotal": {"status": "disabled"}, "AbuseIPDB": {"status": "disabled"}}
    result = score_indicator(indicator, local, sources)
    assert result["verdict"] == "Unknown"
    assert "not proof" in result["summary"]
