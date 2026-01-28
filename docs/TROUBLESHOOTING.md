# Troubleshooting & Hardening

## Common Issues & Fixes

### 1. "My commit is blocked but I swear it's not a secret!"
**Severity: False Positive**
-   **Reason**: You might have a variable named `my_aws_key_id` that is just a placeholder.
-   **Fix**:
    1.  Rename the variable to `example_key` or `placeholder`.
    2.  If strictly necessary, append `# pragma: allow-secret` (Future Feature) or use `git commit --no-verify` (Logged Incident).

### 2. "The scanner crashed on a binary file"
**Severity: Bug**
-   **Resolution**: The scanner has `try/except` blocks (Lines 60-66 in `scan.py`) to handle encoding errors (UTF-8) or binary reads. It will log a `[WARN]` and skip the file rather than crashing the pipeline.

### 3. "Recursion limit reached on node_modules"
**Severity: Performance**
-   **Prevention**: Ensure `.gitignore` is properly set up. The scanner respects gitignore implicitly if running via pre-commit on *staged* files. For full folder scans, explicit exclude logic is recommended in `scan.py`.

## Hardening Measures Implemented
-   **Fail-Open vs Fail-Closed**: We default to **Fail-Closed** on High Severity (Exit code 1).
-   **Safe Regex**: All regex patterns use standard character classes to prevent ReDoS (Regex Denial of Service) attacks.
-   **Stubbed Validation**: Network calls are strictly optional (`--validate`) to prevent accidental leaks of the keys being checked.
