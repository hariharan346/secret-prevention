from src.security_guardian.policy import PolicyEngine
from src.security_guardian.scanner import SecretScanner

def test_scan():
    print("Testing Scanner...")
    policy = PolicyEngine()
    scanner = SecretScanner(policy)
    
    # Run against existing test files
    scanner.scan_path("tests/test_secrets.txt")
    scanner.scan_path("tests/test_context.txt")
    scanner.scan_path("tests/test_entropy.txt")
    
    for issue in scanner.results:
        print(f"[{issue.severity}] {issue.secret_type} in {issue.file_path}")

if __name__ == "__main__":
    test_scan()
