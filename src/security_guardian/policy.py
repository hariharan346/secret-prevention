from typing import List, Dict, Any
from .models import Severity

# Hardcoded defaults (batteries-included)
DEFAULT_CONTEXT_KEYWORDS = ["prod", "production", "live", "main", "master", "key", "secret"]

DEFAULT_PATTERNS = [
    {
        "name": "AWS Access Key",
        "regex": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "severity": Severity.HIGH
    },
    {
        "name": "AWS Secret Key",
        # Improved regex to be less prone to false positives
        "regex": r"(?i)aws_secret_access_key['\"]?\s*(=|:)\s*['\"]?[A-Za-z0-9\/+=]{40}['\"]?",
        "severity": Severity.HIGH
    },
    {
        "name": "GitHub Token",
        "regex": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
        "severity": Severity.HIGH
    },
    {
        "name": "Private Key",
        "regex": r"-----BEGIN\s?((RSA|DSA|EC|OPENSSH|PGP)\s?)?PRIVATE\s?KEY-----",
        "severity": Severity.HIGH
    },
    {
        "name": "Generic Password",
        "regex": r"(?i)(password|passwd|secret|api_key|apikey)['\"]?\s*(=|:)\s*['\"][A-Za-z0-9@#$%^&+=]{8,}['\"]",
        "severity": Severity.MEDIUM
    }
]

class PolicyEngine:
    """
    Manages rules for detection and severity.
    """
    def __init__(self, config_path: str = None):
        self.patterns = DEFAULT_PATTERNS
        self.context_keywords = DEFAULT_CONTEXT_KEYWORDS
        # Future: Load from config_path if provided
    
    def get_action(self, severity: Severity) -> str:
        """
        Returns BLOCK, WARN, or LOG based on severity.
        """
        # Default Enterprise Policy
        if severity == Severity.HIGH:
            return "BLOCK"
        elif severity == Severity.MEDIUM:
            return "WARN"
        return "LOG"
