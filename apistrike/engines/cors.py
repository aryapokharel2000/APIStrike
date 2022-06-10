from typing import List, Optional
from .base import BaseEngine, Finding, Severity


class CORSEngine(BaseEngine):
    NAME    = "CORS Assessment Engine"
    VERSION = "1.0.0"

    # List of malicious origins to test
    PROBE_ORIGINS = [
        "https://evil.com",
        "https://attacker.internal",
        "null",
        "https://notreally.localhost",
    ]

    def run(self, endpoint: str) -> List[Finding]:
        findings = []

        for origin in self.PROBE_ORIGINS:
            # Check preflight (OPTIONS) request
            result = self._probe_preflight(endpoint, origin)
            if result:
                findings.append(result)

            # Check simple (GET) request
            result = self._probe_simple_request(endpoint, origin)
            if result:
                findings.append(result)

        # Check for wildcard origin with credentials
        result = self._probe_wildcard_credentials(endpoint)
        if result:
            findings.append(result)

        return self._deduplicate(findings)

    def _probe_preflight(self, endpoint: str, origin: str) -> Optional[Finding]:
        # Simulate a browser preflight request
        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization, Content-Type",
        }

        response = self.http_client.request("OPTIONS", endpoint, headers=headers)
        if response is None:
            return None

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "").lower().strip()

        # If the origin isn't reflected, we're good
        if acao != origin:
            return None

        credentialled = acac == "true"
        severity = Severity.HIGH if credentialled else Severity.MEDIUM

        return Finding(
            engine=self.NAME,
            endpoint=endpoint,
            severity=severity,
            title=(
                "CORS: Credentialled Origin Reflection on Preflight"
                if credentialled else
                "CORS: Origin Reflection on Preflight Request"
            ),
            description=(
                f"Server returned Access-Control-Allow-Origin: {acao!r} for "
                f"OPTIONS preflight with Origin: {origin!r}. "
                + (
                    f"With Allow-Credentials: true set, an attacker at {origin!r} "
                    "can make authenticated cross-origin requests."
                    if credentialled else
                    "Server reflects arbitrary origins without an allowlist check."
                )
            ),
            evidence={
                "probe_method": "OPTIONS (Preflight)",
                "injected_origin": origin,
                "Access-Control-Allow-Origin": acao,
                "Access-Control-Allow-Credentials": acac or "(absent)",
                "http_status": response.status_code,
                "latency_ms": getattr(response, "latency_ms", None),
            },
            remediation=(
                "Use an explicit server-side allowlist of permitted origins. "
                "Never reflect the incoming Origin header without validation. "
                "Avoid combining wildcard policies with Allow-Credentials."
            ),
        )

    def _probe_simple_request(self, endpoint: str, origin: str) -> Optional[Finding]:
        # Simulate a simple GET request
        response = self.http_client.request("GET", endpoint, headers={"Origin": origin})
        if response is None:
            return None

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "").lower().strip()

        # If the origin isn't reflected, we're good
        if acao != origin:
            return None

        credentialled = acac == "true"
        severity = Severity.HIGH if credentialled else Severity.MEDIUM

        return Finding(
            engine=self.NAME,
            endpoint=endpoint,
            severity=severity,
            title=(
                "CORS: Credentialled Origin Reflection on Simple Request"
                if credentialled else
                "CORS: Origin Reflection on Simple GET Request"
            ),
            description=(
                f"GET request with Origin: {origin!r} got "
                f"Access-Control-Allow-Origin: {acao!r}. "
                + (
                    "Allow-Credentials: true means a malicious page at that origin "
                    "can read the full authenticated response."
                    if credentialled else
                    "Arbitrary origin reflected without allowlist validation."
                )
            ),
            evidence={
                "probe_method": "GET (Simple Request)",
                "injected_origin": origin,
                "Access-Control-Allow-Origin": acao,
                "Access-Control-Allow-Credentials": acac or "(absent)",
                "http_status": response.status_code,
                "latency_ms": getattr(response, "latency_ms", None),
            },
            remediation=(
                "Validate the Origin header against a hardcoded allowlist. "
                "Reject any request whose Origin is not explicitly permitted."
            ),
        )

    def _probe_wildcard_credentials(self, endpoint: str) -> Optional[Finding]:
        # Check if the server allows wildcard origins with credentials
        response = self.http_client.get(endpoint)
        if response is None:
            return None

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "").lower().strip()

        if not (acao == "*" and acac == "true"):
            return None

        return Finding(
            engine=self.NAME,
            endpoint=endpoint,
            severity=Severity.MEDIUM,
            title="CORS: Wildcard Policy Combined with Allow-Credentials",
            description=(
                "Server returns ACAO: * and ACAC: true at the same time. "
                "Browsers reject this per the Fetch spec, but it signals a broken "
                "CORS implementation that may be exploitable in non-browser clients."
            ),
            evidence={
                "Access-Control-Allow-Origin": acao,
                "Access-Control-Allow-Credentials": acac,
                "http_status": response.status_code,
            },
            remediation=(
                "Replace the wildcard ACAO with an explicit list of trusted origins. "
                "Only set Allow-Credentials after validating the origin."
            ),
        )

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        # Remove duplicate findings based on title and endpoint
        seen = set()
        unique = []
        for f in findings:
            key = (f.title, f.endpoint)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
