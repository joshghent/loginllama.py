import hashlib
import hmac
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from .api import Api

API_ENDPOINT = os.getenv("LOGINLLAMA_API_BASE_URL", "https://loginllama.app/api/v1")


class LoginCheckStatus(Enum):
    VALID = "login_valid"
    INVALID = "login_invalid"
    IP_ADDRESS_SUSPICIOUS = "ip_address_suspicious"
    DEVICE_FINGERPRINT_SUSPICIOUS = "device_fingerprint_suspicious"
    LOCATION_FINGERPRINT_SUSPICIOUS = "location_fingerprint_suspicious"
    BEHAVIORAL_FINGERPRINT_SUSPICIOUS = "behavioral_fingerprint_suspicious"
    KNOWN_TOR_EXIT_NODE = "known_tor_exit_node"
    KNOWN_PROXY = "known_proxy"
    KNOWN_VPN = "known_vpn"
    KNOWN_BOTNET = "known_botnet"
    KNOWN_BOT = "known_bot"
    IP_ADDRESS_NOT_USED_BEFORE = "ip_address_not_used_before"
    DEVICE_FINGERPRINT_NOT_USED_BEFORE = "device_fingerprint_not_used_before"
    AI_DETECTED_SUSPICIOUS = "ai_detected_suspicious"
    NEW_LOGIN_LOCATION = "new_login_location"
    IMPOSSIBLE_TRAVEL_DETECTED = "impossible_travel_detected"


@dataclass
class LoginCheck:
    status: str
    message: str
    codes: List[Union[LoginCheckStatus, str]]
    risk_score: int
    environment: str
    meta: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def verify_webhook_signature(
    payload: Union[str, bytes],
    signature: Optional[str],
    secret: str,
) -> bool:
    """
    Verify the X-LoginLlama-Signature header using HMAC-SHA256 and a constant-time compare.
    """
    if not signature or not secret:
        return False

    if isinstance(payload, str):
        payload = payload.encode()

    expected_signature = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)


class LoginLlama:
    def __init__(self, api_token: Optional[str] = None, base_url: Optional[str] = None):
        self.token = api_token or os.getenv("LOGINLLAMA_API_KEY")
        if not self.token:
            raise ValueError("LOGINLLAMA_API_KEY is required")
        self.api = Api({"X-API-KEY": self.token}, base_url or API_ENDPOINT)

    def check_login(
        self,
        request: Any = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        identity_key: Optional[str] = None,
        email_address: Optional[str] = None,
        geo_country: Optional[str] = None,
        geo_city: Optional[str] = None,
        user_time_of_day: Optional[str] = None,
        # camelCase aliases
        ipAddress: Optional[str] = None,
        userAgent: Optional[str] = None,
        identityKey: Optional[str] = None,
        emailAddress: Optional[str] = None,
        geoCountry: Optional[str] = None,
        geoCity: Optional[str] = None,
        userTimeOfDay: Optional[str] = None,
    ) -> LoginCheck:
        if request:
            meta = getattr(request, "META", {}) or {}
            ip_address = (
                ip_address
                or meta.get("HTTP_X_FORWARDED_FOR")
                or meta.get("REMOTE_ADDR")
                or getattr(request, "remote_addr", None)
                or getattr(request, "client", None)
                or "Unavailable"
            )
            headers = getattr(request, "headers", {}) or meta
            user_agent = user_agent or headers.get("User-Agent") or headers.get("HTTP_USER_AGENT")

        final_ip = ip_address or ipAddress
        final_user_agent = user_agent or userAgent
        final_identity_key = identity_key or identityKey
        final_email = email_address or emailAddress
        final_geo_country = geo_country or geoCountry
        final_geo_city = geo_city or geoCity
        final_time = user_time_of_day or userTimeOfDay

        if not final_ip:
            raise ValueError("ip_address is required")
        if not final_user_agent:
            raise ValueError("user_agent is required")
        if not final_identity_key:
            raise ValueError("identity_key is required")

        response = self.api.post(
            "/login/check",
            {
                "ip_address": final_ip,
                "user_agent": final_user_agent,
                "identity_key": final_identity_key,
                "email_address": final_email,
                "geo_country": final_geo_country,
                "geo_city": final_geo_city,
                "user_time_of_day": final_time,
            },
        )

        codes: List[Union[LoginCheckStatus, str]] = []
        for code in response.get("codes", []):
            try:
                codes.append(LoginCheckStatus(code))
            except ValueError:
                codes.append(code)

        return LoginCheck(
            status=response.get("status"),
            message=response.get("message"),
            codes=codes,
            risk_score=response.get("risk_score", 0),
            environment=response.get("environment", "production"),
            meta=response.get("meta"),
            error=response.get("error"),
        )
