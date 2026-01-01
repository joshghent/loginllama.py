import hashlib
import hmac
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from .api import Api
from .context_detector import ContextDetector
from .ip_extractor import IPExtractor

API_ENDPOINT = os.getenv("LOGINLLAMA_API_BASE_URL", "https://loginllama.app/api/v1")


class LoginCheckStatus(Enum):
    """Status codes returned by the LoginLlama API"""

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
    """Response from the LoginLlama API"""

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
    Verify the X-LoginLlama-Signature header using HMAC-SHA256 and constant-time compare

    Args:
        payload: Webhook payload
        signature: X-LoginLlama-Signature header value
        secret: Webhook secret from LoginLlama dashboard

    Returns:
        True if signature is valid
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
    """LoginLlama client for detecting suspicious login attempts"""

    def __init__(self, api_token: Optional[str] = None, base_url: Optional[str] = None):
        """
        Create a new LoginLlama client

        Args:
            api_token: API key (defaults to LOGINLLAMA_API_KEY env var)
            base_url: Base URL for API (defaults to https://loginllama.app/api/v1)
        """
        self.token = api_token or os.getenv("LOGINLLAMA_API_KEY")
        if not self.token:
            raise ValueError("LOGINLLAMA_API_KEY is required")
        self.api = Api({"X-API-KEY": self.token}, base_url or API_ENDPOINT)

    def check(
        self,
        identity_key: str,
        *,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        email_address: Optional[str] = None,
        geo_country: Optional[str] = None,
        geo_city: Optional[str] = None,
        user_time_of_day: Optional[str] = None,
        request: Optional[Any] = None,
    ) -> LoginCheck:
        """
        Check a login attempt for suspicious activity

        IP address and User-Agent are automatically detected from:
        1. Explicit overrides in parameters
        2. Explicit request object
        3. Context (if middleware is used)

        Args:
            identity_key: User identifier (email, username, user ID, etc.)
            ip_address: Override auto-detected IP address
            user_agent: Override auto-detected User-Agent
            email_address: User's email for notifications
            geo_country: Country name or ISO code
            geo_city: City name
            user_time_of_day: User's local time in HH:mm format
            request: Framework request object for explicit extraction

        Returns:
            LoginCheck object with status, risk_score, and codes

        Raises:
            ValueError: If identity_key is missing or context cannot be detected

        Examples:
            # Auto-detect from context (middleware)
            result = loginllama.check('user@example.com')

            # Explicit request passing
            @app.route('/login', methods=['POST'])
            def login():
                result = loginllama.check(
                    request.form['email'],
                    request=request
                )

            # Manual override
            result = loginllama.check(
                'user@example.com',
                ip_address='1.2.3.4',
                user_agent='Custom/1.0'
            )
        """
        if not identity_key:
            raise ValueError("identity_key is required")

        # Extract IP and User-Agent with priority fallback
        final_ip: Optional[str] = ip_address
        final_ua: Optional[str] = user_agent

        # Priority 1: Explicit overrides (already set)

        # Priority 2: Extract from explicit request
        if request and (not final_ip or not final_ua):
            if not final_ip:
                final_ip = IPExtractor.extract(request)
            if not final_ua:
                final_ua = self._extract_user_agent(request)

        # Priority 3: Check context (from middleware)
        if not final_ip or not final_ua:
            context = ContextDetector.get_context()
            if context:
                if not final_ip:
                    final_ip = context.ip_address
                if not final_ua:
                    final_ua = context.user_agent

        # Validation
        if not final_ip:
            raise ValueError(
                "ip_address could not be detected. Pass ip_address= or request= explicitly, "
                "or use the middleware() function."
            )
        if not final_ua:
            raise ValueError(
                "user_agent could not be detected. Pass user_agent= or request= explicitly, "
                "or use the middleware() function."
            )

        # Make API call
        response = self.api.post(
            "/login/check",
            {
                "ip_address": final_ip,
                "user_agent": final_ua,
                "identity_key": identity_key,
                "email_address": email_address,
                "geo_country": geo_country,
                "geo_city": geo_city,
                "user_time_of_day": user_time_of_day,
            },
        )

        # Parse response into LoginCheck
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

    def middleware(self):
        """
        Create middleware for Flask/Django/FastAPI to auto-capture request context

        This middleware stores request information in contextvars,
        allowing check() to automatically access IP and User-Agent.

        Returns:
            Middleware function appropriate for the framework

        Examples:
            # Flask
            app = Flask(__name__)
            loginllama = LoginLlama()

            @app.before_request
            def setup_loginllama():
                loginllama.middleware()()

            @app.route('/login', methods=['POST'])
            def login():
                result = loginllama.check(request.form['email'])
                # IP and User-Agent automatically detected

            # Django (middleware.py)
            from loginllama import LoginLlama

            loginllama = LoginLlama()

            class LoginLlamaMiddleware:
                def __init__(self, get_response):
                    self.get_response = get_response

                def __call__(self, request):
                    from loginllama.context_detector import ContextDetector
                    ContextDetector.set_context(request)
                    return self.get_response(request)

            # FastAPI
            from fastapi import FastAPI, Request

            app = FastAPI()
            loginllama = LoginLlama()

            @app.middleware("http")
            async def loginllama_middleware(request: Request, call_next):
                from loginllama.context_detector import ContextDetector
                ContextDetector.set_context(request)
                response = await call_next(request)
                return response
        """

        def flask_middleware():
            """Flask middleware using before_request"""
            from flask import request as flask_request

            ContextDetector.set_context(flask_request)

        return flask_middleware

    def _extract_user_agent(self, request: Any) -> Optional[str]:
        """Extract User-Agent from request"""
        if not request:
            return None

        # Django
        if hasattr(request, "META"):
            return request.META.get("HTTP_USER_AGENT")

        # Flask/FastAPI
        if hasattr(request, "headers"):
            return request.headers.get("User-Agent") or request.headers.get("user-agent")

        return None
