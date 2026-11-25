"""HTTP client the dashboard uses to reach the SentinelAI API."""
from __future__ import annotations

import requests


class ApiError(RuntimeError):
    def __init__(self, status: int | None, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class ApiClient:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False  # local API: never route through a system proxy

    def _call(self, method: str, path: str, **kwargs):
        try:
            response = self.session.request(method, f"{self.base_url}{path}", timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            raise ApiError(None, f"Cannot reach the API at {self.base_url} ({type(exc).__name__}).") from exc
        if response.status_code >= 400:
            try:
                body = response.json()
                detail = body.get("detail", response.text)
                if body.get("errors"):
                    detail += ": " + "; ".join(f"{e['field']} {e['problem']}" for e in body["errors"])
            except ValueError:
                detail = response.text or response.reason
            raise ApiError(response.status_code, str(detail))
        return response

    def get(self, path: str, **params):
        params = {k: v for k, v in params.items() if v is not None and v != ""}
        return self._call("GET", path, params=params).json()

    def post(self, path: str, payload: dict):
        response = self._call("POST", path, json=payload)
        return response.status_code, response.json()

    def download(self, path: str) -> bytes:
        return self._call("GET", path).content
