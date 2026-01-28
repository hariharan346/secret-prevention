# Enterprise Rollout Strategy

## 1. Centralized Enforcement
To scale this across 1000+ repositories, we do NOT ask developers to copy-paste `security.yml`.
Instead, we use **GitHub Organization Defaults** or **Shared Workflow Templates**.

### Strategy:
1.  **Central Repo**: Store the scanner logic (`src/scan.py` and `config.json`) in a dedicated `security-tools` repo.
2.  **Shared Action**: Publish this tool as a private GitHub Action `my-org/secret-scanner@v1`.
3.  **Mandatory Checks**: Use GitHub Branch Protection Rules to **Require status checks to pass** (specifically the `secret-scan` job) before merging to `main`.

## 2. Adoption Phases
| Phase | Action | Goal |
|:---|:---|:---|
| **Phase 1: Audit Mode** | Run scanner in proper CI pipelines but **Action = LOG** (no blocking). | Collect data on existing leaks. Fix legacy issues silently. |
| **Phase 2: Warn Mode** | Set config to **MEDIUM = WARN, HIGH = WARN**. | Get developers used to seeing the alerts. Gather feedback on false positives. |
| **Phase 3: Prevention Mode** | Set config to **HIGH = BLOCK**. | Turn on the gatekeeper. No new secrets can enter `main`. |

## 3. Local Hooks vs CI/CD
We encourage use of the `pre-commit` hook for **Developer Experience (DX)**—it gives instant feedback.
However, we **DO NOT TRUST IT**.
-   **Hook**: Helper (catch it fast).
-   **CI/CD**: Enforcer (catch it definitely).

## 4. Scaling Updates
By using a central `config.json` fetched at runtime (or baked into the Docker image of the scanner), the Security Team can update the definition of "HIGH Severity" globally without submitting PRs to 1000 repos.
