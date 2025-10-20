# Security Scanning Runbook

## Overview

The agentic automation framework runs multiple security scanners daily to identify vulnerabilities, misconfigurations, and secrets in the codebase.

## Scanners

### 1. pip-audit (Python Dependencies)

**Purpose**: Scan Python packages for known CVEs

**Installation**:
```bash
pip install pip-audit
```

**Usage**:
```bash
pip-audit --format json --output reports/security/python_vulns.json
```

**Output**: JSON file with vulnerability details including:
- Package name and version
- CVE identifiers
- Severity (LOW, MEDIUM, HIGH, CRITICAL)
- Fix recommendations

### 2. Trivy (Containers, IaC, Filesystem)

**Purpose**: Comprehensive security scanner for containers, infrastructure-as-code, and filesystem vulnerabilities

**Installation**:
```bash
# macOS
brew install trivy

# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

**Usage**:
```bash
trivy fs . --format json --output reports/security/trivy.json
```

**Scans for**:
- OS packages vulnerabilities
- Language-specific dependencies (Python, Node.js, Go, etc.)
- IaC misconfigurations (Terraform, CloudFormation, Kubernetes)
- Secrets in code

### 3. Gitleaks (Secrets Detection)

**Purpose**: Detect accidentally committed secrets and credentials

**Installation**:
```bash
# macOS
brew install gitleaks

# Linux
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

**Usage**:
```bash
gitleaks detect --report-format json --report-path reports/security/secrets.json
```

**Detects**:
- API keys
- AWS credentials
- Private keys
- Tokens and passwords
- Database connection strings

### 4. npm audit (JavaScript Dependencies) [Optional]

**Purpose**: Scan Node.js packages for vulnerabilities

**Usage**:
```bash
npm audit --json > reports/security/npm_vulns.json
```

## Automated Workflow

The orchestrator runs all scanners daily via GitHub Actions:

1. **Security Bot** executes scanners and generates:
   - Individual scanner reports in `reports/security/`
   - Aggregated `findings.json` with normalized format
   - Human-readable `daily_report.txt`

2. **Architect Bot** analyzes findings and creates implementation plan

3. **Engineer Bot** opens PRs for low-risk fixes in allowlisted paths

## Manual Scanning

To run scanners manually:

```bash
# Run all scanners
python3 orchestrator/main.py

# Run individual scanner
python3 -c "from orchestrator.scanners import pip_audit; pip_audit.scan()"
```

## Interpreting Results

### Severity Levels

- **CRITICAL**: Immediate attention required, likely exploitable
- **HIGH**: Patch within 7 days
- **MEDIUM**: Patch within 30 days
- **LOW**: Patch when convenient

### False Positives

If a finding is a false positive:

1. Document reason in `docs/security_exceptions.md`
2. Add suppression rule to scanner config
3. Update architect bot prompt to skip this finding

## Troubleshooting

### Scanner not found
```bash
which pip-audit trivy gitleaks
```

Install missing scanners per instructions above.

### Permission denied
```bash
chmod +x /usr/local/bin/gitleaks
```

### Rate limiting (GitHub Actions)
Scanners cache results for 1 hour to avoid re-scanning on retries.

## References

- [pip-audit docs](https://github.com/pypa/pip-audit)
- [Trivy docs](https://aquasecurity.github.io/trivy/)
- [Gitleaks docs](https://github.com/gitleaks/gitleaks)
