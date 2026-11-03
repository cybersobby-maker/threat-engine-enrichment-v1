import pytest

from threatintel.normalizer import IndicatorError, normalize_ioc


def test_normalizes_ipv4_and_detects_non_global():
    result = normalize_ioc("192.0.2.10")
    assert result.ioc_type == "IPv4"
    assert result.normalized == "192.0.2.10"
    assert result.is_public_ip is False
    assert result.notes


def test_normalizes_public_ipv4():
    result = normalize_ioc("8.8.8.8")
    assert result.ioc_type == "IPv4"
    assert result.is_public_ip is True


def test_normalizes_defanged_url():
    result = normalize_ioc("hxxps://login[.]example/path")
    assert result.ioc_type == "URL"
    assert result.normalized == "https://login.example/path"


def test_normalizes_domain_case_and_trailing_dot():
    result = normalize_ioc("Example.COM.")
    assert result.ioc_type == "Domain"
    assert result.normalized == "example.com"


@pytest.mark.parametrize(("value", "expected"), [
    ("a" * 32, "MD5"),
    ("b" * 40, "SHA1"),
    ("c" * 64, "SHA256"),
])
def test_recognizes_hashes(value, expected):
    result = normalize_ioc(value)
    assert result.ioc_type == expected
    assert result.normalized == value


def test_rejects_invalid_domain():
    with pytest.raises(IndicatorError):
        normalize_ioc("not a domain")


def test_rejects_empty_input():
    with pytest.raises(IndicatorError):
        normalize_ioc("  ")


def test_preserves_url_fragment():
    result = normalize_ioc("https://example.com/path#client-route")
    assert result.normalized == "https://example.com/path#client-route"
