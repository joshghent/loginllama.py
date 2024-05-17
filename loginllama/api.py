import requests

class Api:
    def __init__(self, default_headers, url):
        self.headers = {
            "X-LOGINLLAMA-SOURCE": "python-sdk",
            "X-LOGINLLAMA-VERSION": "1",
            "Content-Type": "application/json",
            **default_headers,
        }
        self.base_url = url

    def get(self, url):
        response = requests.get(f"{self.base_url}{url}", headers=self.headers)
        response.raise_for_status()
        return response.json()

    def post(self, url, params={}):
        response = requests.post(f"{self.base_url}{url}", json=params, headers=self.headers)
        response.raise_for_status()
        return response.json()
