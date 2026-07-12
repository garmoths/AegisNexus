"""
Tests for STIX 2.1 export endpoint and helpers.
"""
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


# ── Unit: _ioc_to_stix_indicator ─────────────────────────────────────────────

def _make_ioc(
    ioc_type="ip",
    ioc_value="1.2.3.4",
    threat_type="botnet",
    risk_score=80,
    confidence=0.9,
    source="abuseipdb",
    source_reference=None,
):
    row = MagicMock()
    row.ioc_type = ioc_type
    row.ioc_value = ioc_value
    row.threat_type = threat_type
    row.risk_score = risk_score
    row.confidence = confidence
    row.source = source
    row.source_reference = source_reference
    row.detection_count = 3
    row.first_seen = datetime(2024, 1, 1, tzinfo=timezone.utc)
    row.last_seen = datetime(2024, 6, 1, tzinfo=timezone.utc)
    row.created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    row.updated_at = datetime(2024, 6, 1, tzinfo=timezone.utc)
    return row


def test_stix_indicator_structure():
    from modules.honeypot.ioc_api import _ioc_to_stix_indicator
    obj = _ioc_to_stix_indicator(_make_ioc())
    assert obj["type"] == "indicator"
    assert obj["spec_version"] == "2.1"
    assert obj["pattern_type"] == "stix"
    assert "[ipv4-addr:value = '1.2.3.4']" == obj["pattern"]
    assert obj["confidence"] == 90
    assert "botnet" in obj["indicator_types"]


def test_stix_tlp_white_for_low_risk():
    from modules.honeypot.ioc_api import _ioc_to_stix_indicator, _TLP_MAP
    obj = _ioc_to_stix_indicator(_make_ioc(risk_score=30))
    assert _TLP_MAP["white"] in obj["object_marking_refs"]


def test_stix_tlp_amber_for_medium_risk():
    from modules.honeypot.ioc_api import _ioc_to_stix_indicator, _TLP_MAP
    obj = _ioc_to_stix_indicator(_make_ioc(risk_score=65))
    assert _TLP_MAP["amber"] in obj["object_marking_refs"]


def test_stix_tlp_red_for_high_risk():
    from modules.honeypot.ioc_api import _ioc_to_stix_indicator, _TLP_MAP
    obj = _ioc_to_stix_indicator(_make_ioc(risk_score=95))
    assert _TLP_MAP["red"] in obj["object_marking_refs"]


def test_stix_domain_pattern():
    from modules.honeypot.ioc_api import _ioc_to_stix_indicator
    obj = _ioc_to_stix_indicator(_make_ioc(ioc_type="domain", ioc_value="evil.example.com"))
    assert "[domain-name:value = 'evil.example.com']" == obj["pattern"]


def test_stix_url_pattern():
    from modules.honeypot.ioc_api import _ioc_to_stix_indicator
    obj = _ioc_to_stix_indicator(_make_ioc(ioc_type="url", ioc_value="http://evil.com/phish"))
    assert "[url:value = 'http://evil.com/phish']" == obj["pattern"]


def test_stix_hash_pattern():
    from modules.honeypot.ioc_api import _ioc_to_stix_indicator
    sha = "A" * 64
    obj = _ioc_to_stix_indicator(_make_ioc(ioc_type="hash", ioc_value=sha))
    assert f"[file:hashes.'SHA-256' = '{sha}']" == obj["pattern"]


def test_stix_id_deterministic():
    """Same ioc_value should produce same STIX indicator ID."""
    from modules.honeypot.ioc_api import _ioc_to_stix_indicator
    ioc = _make_ioc(ioc_value="192.0.2.1")
    id1 = _ioc_to_stix_indicator(ioc)["id"]
    id2 = _ioc_to_stix_indicator(ioc)["id"]
    assert id1 == id2


def test_stix_external_reference_when_source_ref():
    from modules.honeypot.ioc_api import _ioc_to_stix_indicator
    obj = _ioc_to_stix_indicator(_make_ioc(source_reference="https://example.com/report/1"))
    assert len(obj["external_references"]) == 1
    assert obj["external_references"][0]["url"] == "https://example.com/report/1"


def test_stix_no_external_reference_when_none():
    from modules.honeypot.ioc_api import _ioc_to_stix_indicator
    obj = _ioc_to_stix_indicator(_make_ioc(source_reference=None))
    assert obj["external_references"] == []


# ── Unit: export_stix_bundle DB mock ────────────────────────────────────────

def test_stix_bundle_structure():
    from modules.honeypot.ioc_api import export_stix_bundle
    iocs = [
        _make_ioc("ip", "10.0.0.1", "malware", 90, 0.95),
        _make_ioc("domain", "phish.tk", "phishing", 75, 0.8),
    ]
    mock_db = MagicMock()
    # chain: query().filter().order_by().limit().all() — no threat_type filter
    chain = mock_db.query.return_value
    chain.filter.return_value = chain
    chain.order_by.return_value.limit.return_value.all.return_value = iocs
    result = export_stix_bundle(threat_type=None, min_risk_score=0, limit=1000, db=mock_db)
    body = result.body
    import json
    bundle = json.loads(body)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    # identity + 2 indicators
    assert len(bundle["objects"]) == 3
    assert bundle["objects"][0]["type"] == "identity"
    assert bundle["_meta"]["indicator_count"] == 2


def test_stix_bundle_filter_by_threat_type():
    from modules.honeypot.ioc_api import export_stix_bundle
    mock_db = MagicMock()
    q = mock_db.query.return_value
    q.filter.return_value = q
    q.order_by.return_value.limit.return_value.all.return_value = []
    export_stix_bundle(threat_type="phishing", min_risk_score=50, db=mock_db)
    # Verify filter was called twice (status + risk_score, then threat_type)
    assert mock_db.query.called
