import re
import time
from typing import List, Optional
from .base import BaseEngine, Finding, Severity


class BOLAEngine(BaseEngine):
    NAME    = "BOLA/IDOR Enumerator"
    VERSION = "1.0.0"

    # Settings for BOLA enumeration
    DEFAULT_ID_START = 1
    DEFAULT_ID_END   = 10
    DEFAULT_DELAY_MS = 50.0
    HIT_THRESHOLD    = 0.3   # flag if 30%+ of IDs return 200

    # Looks for {id} in the endpoint string
    _PLACEHOLDER = re.compile(r"\{id\}", re.IGNORECASE)

    def __init__(self, http_client, id_start=DEFAULT_ID_START, id_end=DEFAULT_ID_END, delay_ms=DEFAULT_DELAY_MS):
        super().__init__(http_client)
        self.id_start = id_start
        self.id_end   = id_end
        self.delay_s  = delay_ms / 1000.0

    def run(self, endpoint: str) -> List[Finding]:
        # Ensure the endpoint has an {id} to replace
        if not self._PLACEHOLDER.search(endpoint):
            return [self._missing_placeholder_finding(endpoint)]

        hits   = []
        errors = []
        total  = self.id_end - self.id_start + 1

        # Iterate through the ID range
        for object_id in range(self.id_start, self.id_end + 1):
            url    = self._PLACEHOLDER.sub(str(object_id), endpoint)
            result = self._probe_id(url, object_id)

            # Record successful and error responses
            if result["status"] == 200:
                hits.append(result)
            elif result["status"] in (500, 502, 503):
                errors.append(result)

            # Rate limiting
            if self.delay_s > 0:
                time.sleep(self.delay_s)

        findings = []

        # If we got successful hits, create a finding
        if hits:
            f = self._build_bola_finding(endpoint, hits, total, len(hits) / total)
            if f:
                findings.append(f)

        # If we caused server errors, flag that too
        if errors:
            findings.append(self._build_error_finding(endpoint, errors))

        return findings

    def _probe_id(self, url: str, object_id: int) -> dict:
        # Make a simple GET request for the specific ID
        response = self.http_client.get(url)
        if response is None:
            return {"object_id": object_id, "url": url, "status": -1, "latency_ms": None}

        return {
            "object_id":  object_id,
            "url":        url,
            "status":     response.status_code,
            "latency_ms": getattr(response, "latency_ms", None),
        }

    def _build_bola_finding(self, template, hits, total, hit_ratio) -> Optional[Finding]:
        # High severity if we hit our threshold, Medium otherwise
        severity = Severity.HIGH if hit_ratio >= self.HIT_THRESHOLD else Severity.MEDIUM

        return Finding(
            engine=self.NAME,
            endpoint=template,
            severity=severity,
            title="BOLA/IDOR: Unauthenticated Object Enumeration",
            description=(
                f"Endpoint {template!r} returned HTTP 200 for {len(hits)}/{total} "
                f"probed IDs ({hit_ratio * 100:.1f}%) without authentication. "
                "Any caller can retrieve records for arbitrary object IDs."
            ),
            evidence={
                "template_url":    template,
                "probed_id_range": f"{self.id_start}-{self.id_end}",
                "total_probed":    total,
                "successful_hits": len(hits),
                "hit_ratio_pct":   round(hit_ratio * 100, 1),
                "hit_ids":         [h["object_id"] for h in hits],
                "hit_urls":        [h["url"]       for h in hits],
            },
            remediation=(
                "Add object-level authorization checks on every endpoint that accepts an ID. "
                "Verify the caller owns or is allowed to access the object before returning data. "
                "Consider using UUIDs instead of sequential integers to reduce enumeration risk."
            ),
        )

    def _build_error_finding(self, template: str, errors: list) -> Finding:
        return Finding(
            engine=self.NAME,
            endpoint=template,
            severity=Severity.LOW,
            title="BOLA/IDOR: Server Errors During Enumeration",
            description=(
                f"Endpoint returned HTTP 5xx for IDs {[e['object_id'] for e in errors]} "
                "during unauthenticated enumeration, suggesting unhandled input paths."
            ),
            evidence={
                "error_ids":   [e["object_id"] for e in errors],
                "error_count": len(errors),
                "sample_urls": [e["url"] for e in errors[:5]],
            },
            remediation=(
                "Return consistent 404 or 403 responses for invalid/unauthorized IDs. "
                "Never leak internal error details in HTTP responses."
            ),
        )

    def _missing_placeholder_finding(self, endpoint: str) -> Finding:
        return Finding(
            engine=self.NAME,
            endpoint=endpoint,
            severity=Severity.INFO,
            title="BOLA/IDOR: No ID Placeholder in Endpoint Template",
            description=(
                f"{endpoint!r} has no {{id}} placeholder. "
                "Supply a template like 'http://host/api/users/{id}' for enumeration."
            ),
            evidence={"endpoint": endpoint},
            remediation="Add an {id} placeholder to the endpoint template.",
        )
