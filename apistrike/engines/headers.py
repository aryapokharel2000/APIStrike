import re
from typing import Dict, List, Tuple
from .base import BaseEngine, Finding, Severity


class HeaderEngine(BaseEngine):
    NAME    = "Verbose Header Analyzer"
    VERSION = "1.0.0"

    # Headers that give away server tech/version info
    DISCLOSURE_HEADERS: Dict[str, Tuple[str, Severity]] = {
        "Server":             ("Discloses web server software identity.",          Severity.MEDIUM),
        "X-Powered-By":       ("Reveals backend framework and version.",           Severity.MEDIUM),
        "X-Runtime":          ("Exposes the server-side runtime environment.",     Severity.LOW),
        "X-AspNet-Version":   ("Exposes ASP.NET framework version.",               Severity.MEDIUM),
        "X-AspNetMvc-Version":("Exposes ASP.NET MVC version.",                    Severity.MEDIUM),
        "X-Generator":        ("Reveals CMS or code-generation tool.",             Severity.LOW),
        "Via":                ("Discloses intermediate proxy identity.",            Severity.LOW),
    }

    # Security headers every API response should include
    REQUIRED_SECURITY_HEADERS: Dict[str, str] = {
        "X-Content-Type-Options":  "Prevents MIME-type sniffing.",
        "X-Frame-Options":         "Mitigates clickjacking via frame control.",
        "Strict-Transport-Security": "Enforces HTTPS-only via HSTS.",
        "Content-Security-Policy": "Restricts resource loading to reduce XSS surface.",
        "Referrer-Policy":         "Controls referrer header leakage on outbound requests.",
    }

    # Regex to find version numbers (e.g., 1.2.3)
    _VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")

    def run(self, endpoint: str) -> List[Finding]:
        # Fetch the endpoint to inspect headers
        response = self.http_client.get(endpoint)
        if response is None:
            return []

        findings = []
        findings.extend(self._check_disclosure_headers(endpoint, response.headers))
        findings.extend(self._check_missing_security_headers(endpoint, response.headers))
        return findings

    def _check_disclosure_headers(self, endpoint: str, headers) -> List[Finding]:
        findings = []

        for header_name, (rationale, base_severity) in self.DISCLOSURE_HEADERS.items():
            value = headers.get(header_name)
            if value is None:
                continue

            # Try to extract a version string from the header value
            match = self._VERSION_RE.search(value)
            version_str = match.group(0) if match else None

            # Bump LOW to MEDIUM if we can extract a specific version number
            severity = (
                Severity.MEDIUM
                if (version_str and base_severity == Severity.LOW)
                else base_severity
            )

            findings.append(Finding(
                engine=self.NAME,
                endpoint=endpoint,
                severity=severity,
                title=f"Information Disclosure via {header_name} Header",
                description=(
                    f"Response includes {header_name!r} with value {value!r}. {rationale}"
                    + (
                        f" Version string {version_str!r} is enumerable for CVE targeting."
                        if version_str else ""
                    )
                ),
                evidence={
                    "header_name": header_name,
                    "header_value": value,
                    "version_string_detected": version_str,
                    "http_status": headers.get("Status", "N/A"),
                },
                remediation=(
                    f"Remove or suppress the {header_name!r} header in your server config. "
                    "Version strings should never appear in production responses."
                ),
            ))

        return findings

    def _check_missing_security_headers(self, endpoint: str, headers) -> List[Finding]:
        findings = []

        for header_name, rationale in self.REQUIRED_SECURITY_HEADERS.items():
            # Check if the required security header is present
            if headers.get(header_name) is not None:
                continue

            findings.append(Finding(
                engine=self.NAME,
                endpoint=endpoint,
                severity=Severity.LOW,
                title=f"Missing Security Header: {header_name}",
                description=(
                    f"Response is missing the {header_name!r} header. {rationale}"
                ),
                evidence={
                    "absent_header": header_name,
                    "headers_present": list(headers.keys()),
                },
                remediation=(
                    f"Add {header_name!r} to all HTTP responses via server config or middleware."
                ),
            ))

        return findings
