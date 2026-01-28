import re
import sys
import os
import argparse
import json
import math
from typing import List, Dict, Any

# Initial Default Configuration (Fallback)
DEFAULT_CONFIG = {
    "severity_actions": {
        "HIGH": "BLOCK",
        "MEDIUM": "WARN",
        "LOW": "LOG"
    },
    "patterns": [] # Should be loaded from file
}

class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class ConfigLoader:
    @staticmethod
    def load_config(config_path: str = "config.json") -> Dict[str, Any]:
        if not os.path.exists(config_path):
            # If no config specific found, look in the script directory or parent
            script_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(script_dir)
            possible_paths = [
                os.path.join(script_dir, "config.json"),
                os.path.join(parent_dir, "config.json")
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    config_path = path
                    break
            else:
                # If still not found, return default (empty patterns is bad but handles crash)
                return DEFAULT_CONFIG

        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"{Colors.YELLOW}[WARN] Failed to load config: {e}. Using defaults.{Colors.RESET}")
            return DEFAULT_CONFIG

class SecretScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.found_issues = []
        self.patterns = config.get("patterns", [])
        self.severity_actions = config.get("severity_actions", DEFAULT_CONFIG["severity_actions"])

    def scan_file(self, filepath: str):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for line_num, line in enumerate(lines, 1):
                    self.scan_line(filepath, line_num, line)
        except Exception as e:
            print(f"{Colors.YELLOW}[WARN] Could not read file {filepath}: {e}{Colors.RESET}")

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def scan_line(self, filepath: str, line_num: int, line: str):
        context_keywords = self.config.get("context_keywords", [])
        found_match = False
        
        # 1. Regex Scan
        for pattern_def in self.patterns:
            regex = pattern_def.get("regex")
            base_severity = pattern_def.get("severity", "LOW")
            name = pattern_def.get("name", "Unknown Secret")
            
            if re.search(regex, line):
                found_match = True
                severity = base_severity
                extra_info = ""
                
                # Context Check: Upgrade MEDIUM -> HIGH if risky keywords found
                if severity == "MEDIUM":
                    for kw in context_keywords:
                        if kw.lower() in line.lower():
                            severity = "HIGH"
                            extra_info = f" (Context: Found '{kw}')"
                            break
                            
                self.found_issues.append({
                    "file": filepath,
                    "line": line_num,
                    "type": name + extra_info,
                    "severity": severity,
                    "content": line.strip()
                })

        # 2. Entropy Scan (Only if no regex match found to avoid duplicates)
        # Scan string literals > 15 chars
        if not found_match:
            strings = re.findall(r"['\"]([A-Za-z0-9/+]{16,})['\"]", line)
            for s in strings:
                entropy = self.calculate_entropy(s)
                if entropy > 4.5:
                     self.found_issues.append({
                        "file": filepath,
                        "line": line_num,
                        "type": f"High Entropy String (Score: {entropy:.2f})",
                        "severity": "MEDIUM", # Warning for now
                        "content": line.strip()
                    })


    def validate_secret(self, secret_type: str, content: str) -> str:
        # SAFE STUB: Does not actually contact cloud providers
        if "AWS" in secret_type:
             if "EXAMPLE" in content:
                 return "✅ (Test Key)"
             return "❓ (Unverified)"
        if "GitHub" in secret_type:
            return "❓ (Unverified)"
        return "N/A"

    def print_report(self, validate: bool = False, output_format: str = "text") -> bool:
        """
        Returns True if check passed (no blocking issues), False otherwise.
        """
        should_block = False
        
        # Determine blocking status first
        for issue in self.found_issues:
            sev = issue["severity"]
            action = self.severity_actions.get(sev, "LOG")
            if action == "BLOCK":
                should_block = True

        if output_format == "json":
            output_data = {
                "scan_results": self.found_issues,
                "summary": {
                    "total_issues": len(self.found_issues),
                    "blocking": should_block
                }
            }
            print(json.dumps(output_data, indent=2))
            return not should_block

        # TEXT OUTPUT
        if not self.found_issues:
            print(f"{Colors.GREEN}✅ No secrets found.{Colors.RESET}")
            return True

        print(f"\n{Colors.RED}🚨 SECRETS DETECTED 🚨{Colors.RESET}")
        print("=" * 60)
        
        for issue in self.found_issues:
            sev = issue["severity"]
            action = self.severity_actions.get(sev, "LOG")
            
            color = Colors.RED if action == "BLOCK" else Colors.YELLOW
            
            validation_msg = ""
            if validate:
                # Basic cleanup of content to extract the key part for checking
                # (Very rough, just for demo)
                key_content = issue['content']
                validation_status = self.validate_secret(issue['type'], key_content)
                validation_msg = f"\n  Cloud Check: {validation_status}"
            
            print(f"{color}[{sev}] {issue['type']} -> Action: {action}{Colors.RESET}")
            print(f"  File: {issue['file']}:{issue['line']}")
            print(f"  Match: {issue['content'][:100]}...{validation_msg}") 
            print("-" * 60)
            
            if validate and action == "BLOCK":
                 print(f"  💡 RECOMMENDATION: Rotate this secret immediately!")
                 print("-" * 60)

        if should_block:
            print(f"\n{Colors.RED}❌ BLOCKING: One or more secrets require blocking.{Colors.RESET}")
            return False
        else:
            print(f"\n{Colors.YELLOW}⚠️  WARNING: Secrets found but policy allows commit.{Colors.RESET}")
            return True

def main():
    parser = argparse.ArgumentParser(description="Secret Leakage Prevention Scanner")
    parser.add_argument("files", metavar="F", type=str, nargs="+", help="Files to scan")
    parser.add_argument("--config", type=str, help="Path to config file", default="config.json")
    parser.add_argument("--validate", action="store_true", help="Simulate cloud validation of secrets")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format (text|json)")
    
    args = parser.parse_args()
    
    config = ConfigLoader.load_config(args.config)
    scanner = SecretScanner(config)
    
    for filepath in args.files:
        if os.path.isfile(filepath):
            scanner.scan_file(filepath)
        elif os.path.isdir(filepath):
             # Simple recursive scan for enterprise readiness
             for root, dirs, files in os.walk(filepath):
                for name in files:
                    scanner.scan_file(os.path.join(root, name))
    
    success = scanner.print_report(validate=args.validate, output_format=args.format)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
