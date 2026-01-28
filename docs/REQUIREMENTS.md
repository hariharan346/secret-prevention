# Requirements & Scope: Secret Leakage Prevention System

## 1. Secret Classifications & Definitions

We define "Secrets" as any sensitive credential that, if exposed, could compromise the security of the application or infrastructure.

### Target Secret Types (Phase 1 Scope)
| Secret Type | Description | Example Pattern (Regex Representation) |
|:---|:---|:---|
| **AWS Access Key** | Identifies an AWS user account | `AKIA[0-9A-Z]{16}` |
| **AWS Secret Key** | Authenticates the AWS user | `[0-9a-zA-Z/+]{40}` |
| **GitHub Private Key** | SSH Private Keys for GitHub auth | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| **GitHub Token** | Personal Access Tokens (classic/fine-grained) | `ghp_[a-zA-Z0-9]{36}` |
| **Generic Password** | Variable assignments containing passwords | `password\s*=\s*['"][a-zA-Z0-9!@#$%^&*]{8,}['"]` |

## 2. Severity Levels

We categorize secrets based on their potential impact and confidence level.

| Severity | Definition | Criteria |
|:---|:---|:---|
| **HIGH** | Critical credential with high confidence match. | - AWS Access Keys<br>- Private PEM Keys<br>- GitHub Tokens (High confidence patterns) |
| **MEDIUM** | Suspected secret or sensitive configuration. | - Generic "password" variable assignments<br>- High entropy strings (Phase 5)<br>- API Keys with lower confidence patterns |
| **LOW** | Informational findings or low confidence matches. | - Internal IP addresses<br>- Todo comments about security<br>- Email addresses (PII) |

## 3. Enforcement Policy (Block vs. Warn)

The system enforces security boundaries based on the detected severity.

| Severity | Action | Rationale |
|:---|:---|:---|
| **HIGH** | **BLOCK** | **Zero Tolerance.** Use `--no-verify` if absolutely necessary (but logged). These secrets must NEVER reach the repository. |
| **MEDIUM** | **WARN** | **Developer Nudge.** Alert the developer but allow the commit to proceed if they confirm it's intentional (FP risk). |
| **LOW** | **LOG** | **Silent Monitoring.** Log for analytics but do not interrupt workflow. |

## 4. Architecture Standards
- **Platform**: Python 3.9+
- **Environment**: Windows (Git Bash compatible) & Linux (CI/CD)
- **Zero-External-Dependencies (Core)**: The core scanner should not rely on heavy external libs if possible, to keep the hook fast.
