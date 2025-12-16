from typing import Any, Dict, Optional

import requests


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

    def post(self, url: str, params: Optional[Dict[str, Any]] = None) -> Any:
        response = requests.post(
            f"{self.base_url}{url}",
            json=params or {},
            headers=self.headers,
            timeout=5,
        )
        response.raise_for_status()
        return response.json()
