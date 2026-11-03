from typing import Any, Dict, Optional

import requests

# Long enough for a normal check, short enough not to hold up a login.
TIMEOUT_SECONDS = 2


def unavailable(message: str) -> Dict[str, Any]:
    return {
        "status": "unavailable",
        "message": message,
        "codes": [],
        "risk_score": 0,
        "environment": "unknown",
    }


class Api:
    def __init__(self, default_headers: Dict[str, str], url: str):
        self.headers: Dict[str, str] = {
            "X-LOGINLLAMA-SOURCE": "python-sdk",
            "X-LOGINLLAMA-VERSION": "1",
            "Content-Type": "application/json",
            **default_headers,
        }
        self.base_url = url

    def get(self, url: str) -> Any:
        response = requests.get(f"{self.base_url}{url}", headers=self.headers, timeout=5)
        response.raise_for_status()
        return response.json()

    # Fails open: when LoginLlama cannot answer, the result says so with a
    # risk score of 0 rather than raising, so an outage never blocks a login.
    # A 4xx still raises, because a bad key or an exhausted quota is a real
    # answer the caller has to fix.
    def post(self, url: str, params: Optional[Dict[str, Any]] = None) -> Any:
        try:
            response = requests.post(
                f"{self.base_url}{url}",
                json=params or {},
                headers=self.headers,
                timeout=TIMEOUT_SECONDS,
            )
        except (requests.ConnectionError, requests.Timeout) as error:
            return unavailable(str(error))

        if response.status_code >= 500:
            return unavailable(f"{response.status_code}: {response.text[:200]}")
        response.raise_for_status()
        try:
            return response.json()
        except ValueError as error:
            return unavailable(f"Response was not JSON: {error}")
