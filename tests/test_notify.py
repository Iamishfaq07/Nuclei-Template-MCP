import urllib.error

from mcp_nuclei.core.notify import notify_webhook


class _FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_notify_webhook_success(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout=10):
        captured["url"] = request.full_url
        captured["data"] = request.data
        return _FakeResponse()

    monkeypatch.setattr("mcp_nuclei.core.notify.urllib.request.urlopen", fake_urlopen)

    result = notify_webhook("https://hooks.example.com/x", "hello", extra={"foo": "bar"})
    assert result.sent is True
    assert result.status_code == 200
    assert b'"text": "hello"' in captured["data"]
    assert b'"foo": "bar"' in captured["data"]


def test_notify_webhook_http_error(monkeypatch):
    def fake_urlopen(request, timeout=10):
        raise urllib.error.HTTPError(request.full_url, 500, "boom", {}, None)

    monkeypatch.setattr("mcp_nuclei.core.notify.urllib.request.urlopen", fake_urlopen)

    result = notify_webhook("https://hooks.example.com/x", "hello")
    assert result.sent is False
    assert result.status_code == 500


def test_notify_webhook_url_error(monkeypatch):
    def fake_urlopen(request, timeout=10):
        raise urllib.error.URLError("dns failure")

    monkeypatch.setattr("mcp_nuclei.core.notify.urllib.request.urlopen", fake_urlopen)

    result = notify_webhook("https://hooks.example.com/x", "hello")
    assert result.sent is False
    assert "dns failure" in result.error
