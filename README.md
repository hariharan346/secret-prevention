Security Guardian

An Enterprise-Grade, Cloud-Native Secret Prevention Platform

Security Guardian is a DevSecOps tool built to prevent credential leakage in modern applications.
It combines regex-based detection, entropy analysis, and context-aware intelligence to identify real secrets while minimizing false positives.

Unlike simple scripts, Security Guardian is a versioned, distributable security platform designed to enforce “Zero Secret Leakage” policies across local development, Git workflows, and CI/CD pipelines.

Key Features

Intelligent secret detection for API keys, private keys, passwords, and cloud credentials (AWS, GitHub, etc.)

Context-aware engine that distinguishes critical secrets from harmless test values

Entropy analysis to detect high-randomness secrets missed by basic regex

Opt-in Git pre-commit hook to scan changes before every commit

Git hygiene enforcement for .env files

Python package installable via pip on Windows, Linux, and macOS

Installation

Install the package using pip:
pip install git+https://github.com/hariharan346/security-guardian.git  

Usage
Manual Scan

Run a scan on your project or any directory:

# Scan current directory
security-guardian scan .

# Scan a specific folder
security-guardian scan src/

# JSON output (useful for dashboards or CI)
security-guardian scan src/ --format json

Scanning Strategy

Security Guardian provides three scan modes to balance precision and coverage.

Default Mode (Tracked Files Only – Recommended)

By default, Security Guardian scans only Git-tracked files.
This mirrors CI/CD pipelines and pre-commit behavior and avoids scanning local junk files.

Scans files returned by git ls-files

Filters supported source extensions (.py, .js, .json, etc.)

Skips untracked files, binaries, .git/, and vendor directories

security-guardian scan .

Include Untracked Files

Scan untracked source files before staging them.

Scans tracked and untracked files

Respects .gitignore

Useful for validating new scripts

security-guardian scan . --include-untracked

All-Files Mode

Perform deep security audits by scanning everything on disk.

Scans all readable files

Skips .git/, node_modules/, venv/, dist/, and build/

Slower and noisier; recommended only for audits

security-guardian scan . --all-files


Note: Binary and unreadable files are always skipped safely.

Install Pre-commit Hook

Enable automatic scanning during git commit:

security-guardian install-hook


What this does:

Verifies the directory is a Git repository

Installs a pre-commit hook in .git/hooks/pre-commit

Blocks commits containing high-severity secrets

Allows commits that contain warnings only

Hook installation is explicit and opt-in.

Git Hygiene Policy

Security Guardian enforces hygiene rules for .env files before scanning code.

Condition	Action	Reason
.env not present	PASS	Clean state
.env listed in .gitignore	PASS	Correctly ignored
.env not listed in .gitignore	WARN	High risk of accidental commit
.gitignore missing	WARN	Repository hygiene issue
.env tracked by Git	BLOCK	Real secret leak detected

Important:
Security Guardian does not scan the contents of .env files by default.
Any tracked .env file is treated as a security violation regardless of content.

Security Philosophy

Security Guardian follows a noise-free security approach:

Block only real risks
High-confidence leaks such as AWS keys or production secrets block commits immediately.

Warn on hygiene issues
Misconfigurations generate warnings without disrupting development flow.

Local-first security
Secrets are caught on the developer’s machine before reaching CI/CD or remote repositories.

Updating Security Guardian

Upgrade to the latest version:

pip install --upgrade security-guardian


The pre-commit hook does not need to be reinstalled after upgrading.

Summary

Security Guardian helps teams:

Detect secrets before they reach Git repositories

Enforce secure Git practices

Reduce alert fatigue

Maintain developer productivity

