import pytest
import requests

from loginllama.api import Api

api = Api({"X-API-KEY": "key"}, "https://api.test/v1")


class FakeResponse:
    def __init__(self, status_code, body=None, text=""):
        self.status_code = status_code
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("not JSON")
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}", response=self)


# An outage must not block logins, so post() returns an "unavailable" result
# instead of raising.
@pytest.mark.parametrize(
    "outage",
    [requests.ConnectionError("refused"), requests.Timeout("timed out")],
)
def test_post_fails_open_when_unreachable(monkeypatch, outage):
    def fake_post(*args, **kwargs):
        raise outage

    monkeypatch.setattr(requests, "post", fake_post)

    result = api.post("/login/check")

    assert result["status"] == "unavailable"
    assert result["risk_score"] == 0
    assert result["codes"] == []


def test_post_fails_open_on_server_error(monkeypatch):
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: FakeResponse(502, text="Bad Gateway")
    )

    assert api.post("/login/check")["status"] == "unavailable"


def test_post_gives_up_after_two_seconds(monkeypatch):
    seen = {}

    def fake_post(*args, **kwargs):
        seen["timeout"] = kwargs["timeout"]
        return FakeResponse(200, {"status": "success"})

    monkeypatch.setattr(requests, "post", fake_post)
    api.post("/login/check")

    assert seen["timeout"] == 2


def test_post_still_raises_on_a_client_error(monkeypatch):
    monkeypatch.setattr(
        requests,
        "post",
        lambda *a, **k: FakeResponse(401, {"errors": [{"code": "unauthorized"}]}),
    )

    with pytest.raises(requests.HTTPError):
        api.post("/login/check")
