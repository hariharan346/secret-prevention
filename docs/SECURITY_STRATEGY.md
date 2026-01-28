# Enterprise Security Strategy: Secret Leakage Prevention

## 1. Executive Summary
This document defines the governance policy for the "Enterprise Secret Leakage Prevention System". The goal is to enforce a **Zero-Secret-Leakage** policy across the organization's entire codebase, prioritizing automated enforcement over manual vigilance.

## 2. Threat Model
-   **Asset**: Infrastructure Credentials (AWS Keys, K8s Configs, Database Passwords, API Tokens).
-   **Threat**: Accidental commitment to Git repositories (Public or Private).
-   **Impact**: Full infrastructure compromise, data exfiltration, massive financial loss.
-   **Control Point**: The CI/CD Pipeline.

## 3. Secret Classification & Definitions

| Classification | Definition | Examples | Severity |
|:---|:---|:---|:---|
| **Tier 1 (Critical)** | Credentials providing direct, unauthorized access to infrastructure or user data. | AWS Access Keys, Private Keys (PEM), Stripe API Keys, Database Connection Strings with Passwords. | **HIGH** |
| **Tier 2 (Sensitive)** | Secrets that are dangerous but require context or are ambiguous. | Generic "password" variables, High Entropy strings without specific patterns, Internal Test Tokens. | **MEDIUM** |
| **Tier 3 (Info)** | Non-critical sensitive info or PII. | Internal IP ranges, Emails, TODOs mentioning security. | **LOW** |

## 4. Enforcement Policy

We adhere to the **Block on Critical, Verify on Sensitive** philosophy.

| Severity | Action | CI/CD Behavior | Local Hook Behavior |
|:---|:---|:---|:---|
| **HIGH** | **BLOCK** | **FAIL BUILD** | Reject Commit |
| **MEDIUM** | **WARN** | Pass with Warnings | Alert Developer |
| **LOW** | **LOG** | Silent Log | Silent |

## 5. The "CI/CD Authority" Doctrine
In a large enterprise, we cannot trust individual developer environments:
1.  **Hooks are Optional**: Developers can bypass local hooks (`git commit --no-verify`) or delete them.
2.  **Environments Vary**: A Windows laptop might behave differently than a purely Linux CI runner.
3.  **Audibility**: CI/CD provides a non-repudiable log of security checks.

**Therefore, the CI/CD pipeline is the single source of truth.** If a secret passes local checks but is caught in CI, the code is rejected, and the Pull Request is blocked.

## 6. Non-Goals (Scope Control)
-   **History Rewriting**: We will not automatically rewrite Git history for existing leaks (requires BFG/Java tools). We focus on *prevention*.
-   **Binary Scanning**: We do not scan compiled binaries or images, only source text.
-   **Malware Detection**: This is not an antivirus; it is a credential scanner.
