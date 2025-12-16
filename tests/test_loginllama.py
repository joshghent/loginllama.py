import hashlib
import hmac

import pytest

from loginllama.api import Api
from loginllama.loginllama import (
    LoginCheckStatus,
    LoginLlama,
    verify_webhook_signature,
)


def mock_request(ip: str, user_agent: str):
    class MockRequest:
        META = {
            "HTTP_X_FORWARDED_FOR": ip,
            "REMOTE_ADDR": ip,
            "HTTP_USER_AGENT": user_agent,
        }
        headers = {"User-Agent": user_agent}
        remote_addr = ip

    return MockRequest()


def test_check_valid_login(monkeypatch):
    client = LoginLlama(api_token="mockToken")

    def fake_post(self, url, params):
        assert params["ip_address"] == "192.168.1.1"
        assert params["user_agent"] == "Mozilla/5.0"
        assert params["identity_key"] == "validUser"
        return {
            "status": "success",
            "message": "Valid login",
            "codes": ["login_valid"],
            "risk_score": 2,
            "environment": "staging",
            "meta": {"new_device_login": False},
        }

    monkeypatch.setattr(Api, "post", fake_post)

    result = client.check_login(
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0",
        identity_key="validUser",
    )

    assert result.status == "success"
    assert result.message == "Valid login"
    assert LoginCheckStatus.VALID in result.codes
    assert result.risk_score == 2
    assert result.environment == "staging"
    assert result.meta == {"new_device_login": False}


def test_check_invalid_login_raises(monkeypatch):
    client = LoginLlama(api_token="mockToken")

    def fake_post(self, url, params):
        raise Exception("Login check failed")

    monkeypatch.setattr(Api, "post", fake_post)

    with pytest.raises(Exception) as exc:
        client.check_login(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            identity_key="invalidUser",
        )

    assert str(exc.value) == "Login check failed"


@pytest.mark.parametrize(
    "kwargs,expected_message",
    [
        ({"user_agent": "ua", "identity_key": "id"}, "ip_address is required"),
        ({"ip_address": "ip", "identity_key": "id"}, "user_agent is required"),
        ({"ip_address": "ip", "user_agent": "ua"}, "identity_key is required"),
    ],
)
def test_missing_required_fields(kwargs, expected_message):
    client = LoginLlama(api_token="mockToken")
    with pytest.raises(ValueError, match=expected_message):
        client.check_login(**kwargs)


def test_extracts_ip_and_user_agent_from_request(monkeypatch):
    client = LoginLlama(api_token="mockToken")

    def fake_post(self, url, params):
        return {
          "status": "success",
          "message": "Valid login",
          "codes": ["login_valid"],
          "risk_score": 1,
          "environment": "production",
        }

    monkeypatch.setattr(Api, "post", fake_post)

    req = mock_request("192.168.1.1", "Mozilla/5.0")
    result = client.check_login(request=req, identity_key="validUser")

    assert result.status == "success"
    assert LoginCheckStatus.VALID in result.codes


def test_webhook_signature_verification():
    payload = b'{"event":"login.checked"}'
    secret = "secret"
    signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    assert verify_webhook_signature(payload, signature, secret) is True
    assert verify_webhook_signature(payload, "deadbeef", secret) is False
    assert verify_webhook_signature(payload, signature, "wrong") is False
