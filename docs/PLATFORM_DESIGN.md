# Platform Design: security-guardian

## 1. Philosophy: Security as a Product
In large enterprises, we cannot rely on 1000 different teams writing their own regex scripts. Security must be standardized.
We are building `security-guardian` as a **Versioned Internal Product**.

-   **It is a Tool**: Distributed as a Python package (pip install).
-   **It is Versioned**: Allows safe rollouts (v1.0 -> v1.1).
-   **It is Enforced**: CI/CD pipelines fail if the tool detects critical issues.

## 2. Roles & Responsibilities

| Role | Responsibility |
|:---|:---|
| **Platform / SecOps Team** | - Develops and maintains `security-guardian`.<br>- Defines the global `config.json` (Policy).<br>- Handle false positives by updating the tool core.<br>- Releases new versions with improved detection. |
| **Application Developers** | - Install the tool locally for fast feedback (optional).<br>- **CANNOT** disable the checks in CI/CD.<br>- Must rotate secrets if blocked by the tool. |

## 3. CLI Specification
The tool will be a Command Line Interface (CLI) called `security-guardian`.

### Usage
```bash
# Basic Scan
security-guardian scan ./src

# Scan with Cloud Verification (Optional)
security-guardian scan ./src --validate

# JSON Output for CI/CD
security-guardian scan ./src --format json
```

### Exit Codes (The Contract)
The exit code is the API between the Tool and the CI/CD Pipeline.

| Exit Code | Meaning | CI/CD Action |
|:---|:---|:---|
| **0** | **Success**. No secrets, or only LOW/MEDIUM warnings found. | **PASS** |
| **1** | **Failure**. HIGH severity secrets detected. | **BLOCK / FAIL** |
| **2** | **System Error**. The tool crashed or invalid arguments. | **FAIL** |

## 4. Why this Architecture?
1.  **Centralized Logic**: Regex improvements happen in ONE place (the package), and everyone gets them on update.
2.  **Immutability**: App teams cannot edit the scanner code to bypass checks (because they install it as a package).
3.  **Scalability**: Works for 1 repo or 10,000 repos using the same CI template.
