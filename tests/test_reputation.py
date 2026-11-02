import json
from types import SimpleNamespace

import pytest

from sentinel import reputation


HASH = "a" * 64


def test_canned_adapters_skip_malformed_and_fit_feed_shape():
    cases = (
        (reputation.MALWAREBAZAAR, {"data": [{"sha256_hash": HASH}, {"sha256_hash": "bad"}]}, HASH),
        (reputation.URLHAUS, {"urls": [{"url": "https://bad.example/a"}, {"url": "file:///x"}]},
         "https://bad.example/a"),
        (reputation.THREATFOX, {"data": [{"ioc_type": "sha256_hash", "ioc": HASH},
                                         {"ioc_type": "domain", "ioc": "bad.example"}]}, HASH),
        (reputation.THREATFOX_URLS, {"data": [{"ioc_type": "url", "ioc": "https://bad.example/a"},
                                              {"ioc_type": "sha256_hash", "ioc": HASH}]},
         "https://bad.example/a"),
    )
    for adapter, response, expected in cases:
        seen = []

        def transport(url, headers, body, limit):
            seen.append((url, headers, body, limit))
            return json.dumps(response).encode()

        result = adapter.fetch(transport, "test-key")
        assert result.values == (expected,)
        assert result.skipped == 1
        feed = adapter.as_feed(result)
        assert feed.table == adapter.table
        assert list(feed.parse("")) == [expected]
        assert seen[0][1]["Auth-Key"] == "test-key"


def test_known_bad_feed_hit_enters_core_hash_table():
    class Builder:
        rows = []

        def add_hashes(self, rows):
            self.rows.extend(rows)

    builder = Builder()
    result = reputation.parse_malwarebazaar(json.dumps({"data": [{"sha256_hash": HASH}]}).encode())
    assert reputation.MALWAREBAZAAR.apply(builder, result) == 1
    assert builder.rows == [(HASH, "malwarebazaar_api", None)]


def test_response_caps_and_row_truncation():
    with pytest.raises(ValueError):
        reputation.parse_malwarebazaar(b"x" * 8, limit=7)
    with pytest.raises(ValueError):
        reputation.MALWAREBAZAAR.fetch(lambda *args: b"x" * 8, "key", limit=7)
    assert reputation.parse_malwarebazaar(json.dumps({"data": [{"sha256_hash": "?"}]}).encode()).skipped == 1


def test_virustotal_off_key_rate_gap_and_supporting_only():
    called = []

    def transport(url, headers, body, limit):
        called.append((url, body))
        return json.dumps({"data": {"attributes": {"last_analysis_stats":
                           {"malicious": 2, "undetected": 68}}}}).encode()

    settings = SimpleNamespace(virustotal_enabled=False, virustotal_api_key="")
    lookup = reputation.VirusTotal(transport, settings, clock=lambda: 100.0)
    assert lookup.lookup_download(HASH).status == "DISABLED"
    settings.virustotal_enabled = True
    assert lookup.lookup_download(HASH).reason == "missing_key"
    settings.virustotal_api_key = "test-key"
    hit = lookup.lookup_download(HASH)
    assert (hit.status, hit.malicious, hit.total) == ("SUPPORTING", 2, 70)
    assert called == [(f"https://www.virustotal.com/api/v3/files/{HASH}", None)]
    assert lookup.lookup_download(HASH).reason == "rate_limited"
    assert reputation.VirusTotal(lambda *args: b"{", settings, clock=lambda: 200).lookup_download(HASH).status == "GAP"


def test_api_feeds_use_the_key_and_reach_a_snapshot_shape():
    from sentinel.reputation import api_feeds

    seen = []

    def transport(url, headers, body, limit):
        seen.append(headers["Auth-Key"])
        return b'{"urls": [{"url": "http://bad.example/a"}], "data": []}'

    feeds = api_feeds("key", transport)
    assert [f.name for f in feeds] == ["urlhaus_api", "threatfox_api", "threatfox_urls_api"]
    urlhaus = feeds[0]
    assert list(urlhaus.parse(urlhaus.pull())) == ["http://bad.example/a"]
    assert seen == ["key"]


def test_no_key_means_no_api_feed(monkeypatch):
    from sentinel import config, feeds

    assert not any(f.pull for f in feeds.configured_feeds(config.Settings()))
    keyed = config.Settings(abusech_auth_key="key")
    assert sum(1 for f in feeds.configured_feeds(keyed) if f.pull) == 3


def test_transport_refuses_plain_http():
    from sentinel.reputation import http_transport

    with pytest.raises(ValueError):
        http_transport("http://example.com", {}, None, 10)
