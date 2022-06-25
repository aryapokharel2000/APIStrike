import datetime
import time
from typing import Any, Callable, Dict, List, Optional

from ..engines.base    import Finding, Severity
from ..engines.bola    import BOLAEngine
from ..engines.cors    import CORSEngine
from ..engines.headers import HeaderEngine
from ..utils.http_client import HTTPClient


class ScanConfig:
    # All available engines
    ALL_ENGINES = ("cors", "headers", "bola")

    def __init__(
        self,
        base_url:       str,
        endpoints:      List[str],
        bola_templates: Optional[List[str]] = None,
        engines:        Optional[List[str]] = None,
        bola_id_start:  int   = 1,
        bola_id_end:    int   = 10,
        bola_delay_ms:  float = 50.0,
        timeout:        tuple = (5, 10),
        verify_ssl:     bool  = True,
    ):
        # Store configuration options
        self.base_url       = base_url.rstrip("/")
        self.endpoints      = endpoints
        self.bola_templates = bola_templates or []
        self.engines        = [e.lower() for e in (engines or list(self.ALL_ENGINES))]
        self.bola_id_start  = bola_id_start
        self.bola_id_end    = bola_id_end
        self.bola_delay_ms  = bola_delay_ms
        self.timeout        = timeout
        self.verify_ssl     = verify_ssl


class ScanResult:
    def __init__(self, config: ScanConfig):
        self.config   = config
        self.findings: List[Finding] = []
        
        # Track metadata about the scan execution
        self.metadata: Dict[str, Any] = {
            "scan_start":           None,
            "scan_end":             None,
            "duration_seconds":     None,
            "total_findings":       0,
            "findings_by_severity": {s.value: 0 for s in Severity},
            "engines_run":          [],
            "endpoints_probed":     0,
        }

    def add_findings(self, findings: List[Finding]):
        self.findings.extend(findings)

    def finalise(self):
        # Sort findings by severity
        self.findings.sort(key=lambda f: f.severity.weight, reverse=True)
        self.metadata["total_findings"] = len(self.findings)
        
        # Count findings by severity level
        for f in self.findings:
            self.metadata["findings_by_severity"][f.severity.value] += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.findings],
        }


class Scanner:
    def __init__(self, config: ScanConfig, progress_callback: Optional[Callable[[str], None]] = None):
        self.config  = config
        self._log    = progress_callback or (lambda msg: None)
        
        # Initialize our HTTP client
        self._client = HTTPClient(
            base_url=config.base_url,
            timeout=config.timeout,
            verify_ssl=config.verify_ssl,
        )

    def run(self) -> ScanResult:
        result     = ScanResult(self.config)
        wall_start = time.perf_counter()
        result.metadata["scan_start"] = datetime.datetime.utcnow().isoformat() + "Z"
        engines_run = []

        probes_count = 0

        # Run CORS Engine
        if "cors" in self.config.engines:
            engines_run.append("CORSEngine")
            engine = CORSEngine(self._client)
            self._log(f"[cors] Probing {len(self.config.endpoints)} endpoint(s)...")
            
            for ep in self.config.endpoints:
                self._log(f"  -> {ep}")
                findings = engine.run(ep)
                result.add_findings(findings)
                probes_count += 1

        # Run Header Analysis Engine
        if "headers" in self.config.engines:
            engines_run.append("HeaderEngine")
            engine = HeaderEngine(self._client)
            self._log(f"[headers] Probing {len(self.config.endpoints)} endpoint(s)...")
            
            for ep in self.config.endpoints:
                self._log(f"  -> {ep}")
                findings = engine.run(ep)
                result.add_findings(findings)
                probes_count += 1

        # Run BOLA Enumeration Engine
        if "bola" in self.config.engines and self.config.bola_templates:
            engines_run.append("BOLAEngine")
            engine = BOLAEngine(
                self._client,
                id_start=self.config.bola_id_start,
                id_end=self.config.bola_id_end,
                delay_ms=self.config.bola_delay_ms,
            )
            self._log(f"[bola] Enumerating {len(self.config.bola_templates)} template(s)...")
            
            for template in self.config.bola_templates:
                self._log(f"  -> {template}")
                findings = engine.run(template)
                result.add_findings(findings)
                probes_count += 1

        # Calculate duration and finalize results
        duration = time.perf_counter() - wall_start
        result.metadata["scan_end"]         = datetime.datetime.utcnow().isoformat() + "Z"
        result.metadata["duration_seconds"] = round(duration, 3)
        result.metadata["engines_run"]      = engines_run
        result.metadata["endpoints_probed"] = probes_count
        
        result.finalise()
        self._client.close()
        return result
