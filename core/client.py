"""Thin client for the Splunk Observability Cloud REST API.

Handles auth header, retries on HTTP 429 / 5xx with backoff, and pagination.
Every module talks to the API only through this class.
"""
import time

import requests


class ApiError(Exception):
    def __init__(self, status: int, body: str, method: str, path: str):
        self.status = status
        self.body = body
        super().__init__(f"{method} {path} -> HTTP {status}: {body[:300]}")


class O11yClient:
    def __init__(self, settings):
        self.base = settings.api_url
        self.timeout = settings.timeout
        self.max_retries = settings.max_retries
        self.session = requests.Session()
        self.session.headers.update(
            {"X-SF-Token": settings.token, "Content-Type": "application/json"}
        )

    def request(self, method: str, path: str, params=None, json=None):
        url = f"{self.base}{path}"
        for attempt in range(self.max_retries + 1):
            resp = self.session.request(
                method, url, params=params, json=json, timeout=self.timeout
            )
            retryable = resp.status_code == 429 or resp.status_code >= 500
            if retryable and attempt < self.max_retries:
                time.sleep(self._wait_seconds(resp, attempt))
                continue
            if not resp.ok:
                raise ApiError(resp.status_code, resp.text, method, path)
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return resp.text
        raise ApiError(0, "retries exhausted", method, path)

    @staticmethod
    def _wait_seconds(resp, attempt: int) -> float:
        try:
            return min(float(resp.headers.get("Retry-After")), 60.0)
        except (TypeError, ValueError):
            return min(2 ** attempt, 60)

    def get(self, path, params=None):
        return self.request("GET", path, params=params)

    def post(self, path, json=None):
        return self.request("POST", path, json=json)

    def put(self, path, json=None):
        return self.request("PUT", path, json=json)

    def delete(self, path):
        return self.request("DELETE", path)

    def paginate(self, path: str, params=None, page_size: int = 100):
        """Yield every result across pages (offset/limit style)."""
        offset = 0
        while True:
            query = dict(params or {}, limit=page_size, offset=offset)
            data = self.get(path, params=query) or {}
            results = data.get("results", [])
            yield from results
            offset += len(results)
            if not results or offset >= data.get("count", 0):
                break
