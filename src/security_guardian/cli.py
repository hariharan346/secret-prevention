import argparse
import sys
import json
import os
from .policy import PolicyEngine
from .scanner import SecretScanner
from .validator import SecretValidator
from .models import Severity

def main():
    parser = argparse.ArgumentParser(description="Security Guardian - Enterprise Secret Scanner")
    parser.add_argument("path", help="Path to file or directory to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--validate", action="store_true", help="Attempt to validate found secrets")
    parser.add_argument("--exclude", nargs="+", default=[], help="Patterns to exclude from scan")
    
    args = parser.parse_args()

    # Phase 2: Load Ignore File
    ignore_file_path = ".security-guardian-ignore"
    if os.path.exists(ignore_file_path):
        with open(ignore_file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    args.exclude.append(line)
    
    # Initialize Components
    policy = PolicyEngine()
    scanner = SecretScanner(policy, exclude_patterns=args.exclude)
    
    # Run Scan
    scanner.scan_path(args.path)
    
    # Determine Block/Warn
    should_block = False
    results_out = []
    
    for issue in scanner.results:
        action = policy.get_action(issue.severity)
        if action == "BLOCK":
            should_block = True
            
        # Optional Verification
        val_status = "N/A"
        if args.validate:
            val_status = SecretValidator.validate(issue.secret_type, issue.content_snippet)
            
        results_out.append({
            "file": issue.file_path,
            "line": issue.line_number,
            "type": issue.secret_type,
            "severity": issue.severity.value,
            "action": action,
            "content": issue.content_snippet,
            "validation": val_status
        })

    # Output
    if args.format == "json":
        print(json.dumps({"blocking": should_block, "issues": results_out}, indent=2))
    else:
        # Text Output
        if not results_out:
            print("✅ No secrets found.")
        else:
            print("\n🚨 SCAN COMPLETE: Issues Found")
            for res in results_out:
                icon = "❌" if res['action'] == "BLOCK" else "⚠️"
                print(f"{icon} [{res['severity']}] {res['type']} -> {res['action']}")
                print(f"   File: {res['file']}:{res['line']}")
                print(f"   Snippet: {res['content']}")
                if args.validate:
                    print(f"   Cloud Check: {res['validation']}")
                print("-" * 40)
    
    # Exit Code
    if should_block:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
