from dataclasses import dataclass
from enum import Enum
from typing import Optional, List

class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class ScanResult:
    file_path: str
    line_number: int
    secret_type: str
    severity: Severity
    content_snippet: str
    remediation_suggestion: Optional[str] = None
    validation_status: str = "N/A"

@dataclass
class ScanSummary:
    total_files: int
    total_issues: int
    blocking_violations: int
    results: List[ScanResult]
