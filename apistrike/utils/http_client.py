import time
from typing import Any, Dict, Optional
import requests
from requests import Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class HTTPClient:
    USER_AGENT = "APIStrike/1.0.0 Security Scanner (authorized research)"

    def __init__(self, base_url="", timeout=(5, 10), allow_redirects=True, extra_headers=None, verify_ssl=True):
        self.base_url        = base_url.rstrip("/")
        self.timeout         = timeout
        self.allow_redirects = allow_redirects
        self.verify_ssl      = verify_ssl

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.USER_AGENT,
            "Accept":     "application/json, */*",
        })
        if extra_headers:
            self.session.headers.update(extra_headers)

        # Resilient Retry adapter using allowed_methods (compatible with urllib3 2.x)
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, url: str, **kwargs) -> Optional[Response]:
        return self.request("GET", url, **kwargs)

    def options(self, url: str, **kwargs) -> Optional[Response]:
        return self.request("OPTIONS", url, **kwargs)

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> Optional[Response]:
        full_url = url if url.startswith("http") else f"{self.base_url}/{url.lstrip('/')}"

        try:
            start    = time.perf_counter()
            response = self.session.request(
                method=method,
                url=full_url,
                headers=headers or {},
                timeout=self.timeout,
                allow_redirects=self.allow_redirects,
                verify=self.verify_ssl,
                **kwargs,
            )
            response.latency_ms = round((time.perf_counter() - start) * 1000, 2)
            return response

        except requests.exceptions.ConnectionError as e:
            print(f"[HTTPClient] Connection error: {full_url} — {e}")
            return None
        except requests.exceptions.Timeout as e:
            print(f"[HTTPClient] Timeout: {full_url} — {e}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[HTTPClient] Request failed: {full_url} — {e}")
            return None

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
