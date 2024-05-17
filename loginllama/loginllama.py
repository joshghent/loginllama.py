import os
from enum import Enum
from .api import Api
from typing import Optional

API_ENDPOINT = "https://loginllama.app/api/v1"

class LoginCheckStatus(Enum):
    VALID = "login_valid"
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

class LoginCheck:
    def __init__(self, status, message, codes):
        self.status = status
        self.message = message
        self.codes = [LoginCheckStatus(code) for code in codes]

class LoginLlama:
    def __init__(self, api_token: Optional[str] = None):
        self.token = api_token or os.getenv("LOGINLLAMA_API_KEY")
        self.api = Api({"X-API-KEY": self.token}, API_ENDPOINT)

    def check_login(self, request=None, ip_address=None, user_agent=None, identity_key=None,
                    email_address=None, geo_country=None, geo_city=None, user_time_of_day=None):
        if request:
            ip_address = (request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR') or
                          request.remote_addr or 'Unavailable')
            user_agent = request.META.get('HTTP_USER_AGENT')

        if not ip_address:
            raise ValueError("ip_address is required")
        if not user_agent:
            raise ValueError("user_agent is required")
        if not identity_key:
            raise ValueError("identity_key is required")

        response = self.api.post("/login/check", {
            "ip_address": ip_address,
            "user_agent": user_agent,
            "identity_key": identity_key,
            "email_address": email_address,
            "geo_country": geo_country,
            "geo_city": geo_city,
            "user_time_of_day": user_time_of_day,
        })

        return LoginCheck(response['status'], response['message'], response['codes'])
