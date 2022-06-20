import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


# Define severity levels for our findings
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def weight(self) -> int:
        # Used for sorting findings from most to least severe
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]


# Data structure to hold vulnerability information
@dataclass
class Finding:
    engine:      str
    endpoint:    str
    severity:    Severity
    title:       str
    description: str
    evidence:    Dict[str, Any] = field(default_factory=dict)
    remediation: str            = ""
    timestamp:   str            = field(
        default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z"
    )

    def to_dict(self) -> Dict[str, Any]:
        # Convert finding to dictionary for JSON output
        return {
            "engine":      self.engine,
            "endpoint":    self.endpoint,
            "severity":    self.severity.value,
            "title":       self.title,
            "description": self.description,
            "evidence":    self.evidence,
            "remediation": self.remediation,
            "timestamp":   self.timestamp,
        }


# Base class that all vulnerability engines inherit from
class BaseEngine:
    NAME    = "Base Engine"
    VERSION = "1.0.0"

    def __init__(self, http_client) -> None:
        # Share the HTTP client across all engines
        self.http_client = http_client

    def run(self, endpoint: str) -> List[Finding]:
        # Needs to be implemented by child classes
        raise NotImplementedError(f"{self.__class__.__name__} must implement run().")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.NAME!r})"
