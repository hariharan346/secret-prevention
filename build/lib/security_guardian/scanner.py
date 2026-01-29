import re
import math
import os
from typing import List
from .models import ScanResult, Severity, ScanSummary
from .policy import PolicyEngine

class SecretScanner:
    def __init__(self, policy: PolicyEngine, exclude_patterns: List[str] = None):
        self.policy = policy
        self.exclude_patterns = exclude_patterns or []
        self.results: List[ScanResult] = []

    def _is_excluded(self, path: str) -> bool:
        path = os.path.normpath(path)
        for pattern in self.exclude_patterns:
            if os.path.normpath(pattern) in path:
                return True
        return False

    def scan_path(self, path: str):
        if self._is_excluded(path):
            return

        if os.path.isfile(path):
            self._scan_file(path)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                # Modify dirs in-place to skip excluded directories during traversal
                dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]
                
                for name in files:
                    full_path = os.path.join(root, name)
                    if not self._is_excluded(full_path):
                        self._scan_file(full_path)

    def _scan_file(self, filepath: str):
        try:
            # Skip large files or binary files check could go here
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for i, line in enumerate(lines, 1):
                    self._scan_line(filepath, i, line)
        except Exception:
            # logging could go here
            pass

    def _scan_line(self, filepath: str, line_num: int, line: str):
        found_match = False
        
        # 1. Regex Scan
        for pattern in self.policy.patterns:
            compiled_regex = pattern.get("compiled")
            if not compiled_regex:
                continue

            try:
                if compiled_regex.search(line):
                    found_match = True
                    
                    # Determine Severity (Context Aware)
                    severity = pattern["severity"]
                    detected_name = pattern["name"]
                    
                    if severity == Severity.MEDIUM:
                        for kw in self.policy.context_keywords:
                            if kw.lower() in line.lower():
                                severity = Severity.HIGH
                                detected_name += f" (Context: {kw})"
                                break
                                
                    self.results.append(ScanResult(
                        file_path=filepath,
                        line_number=line_num,
                        secret_type=detected_name,
                        severity=severity,
                        content_snippet=line.strip()
                    ))
            except Exception:
                continue

        # 2. Entropy Scan (If no regex match)
        if not found_match:
            self._scan_entropy(filepath, line_num, line)

    def _scan_entropy(self, filepath: str, line_num: int, line: str):
         # Extract potential secret strings (assignments)
         strings = re.findall(r"['\"]([A-Za-z0-9/+]{16,})['\"]", line)
         for s in strings:
             entropy = self._calculate_entropy(s)
             if entropy > 4.5: # Threshold
                 self.results.append(ScanResult(
                    file_path=filepath,
                    line_number=line_num,
                    secret_type=f"High Entropy String ({entropy:.2f})",
                    severity=Severity.MEDIUM,
                    content_snippet=line.strip()
                ))

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return - sum([p * math.log(p) / math.log(2.0) for p in prob])
