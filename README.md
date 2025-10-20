# Agentic Automation (Phase 2)

![Workflow Status](https://github.com/pcutter1/deepcutts_ecommerce-automation/actions/workflows/automation.yml/badge.svg)

Autonomous bots for security + CI hygiene under human-approved guardrails.

## Features

- **Security Scanning**: pip-audit, trivy, gitleaks integration
- **Automated Planning**: Architect bot creates implementation plans from findings
- **PR Creation**: Engineer bot opens PRs for low-risk fixes (GitHub integration optional)
- **Metrics Tracking**: Autonomy ratio, scan trends, historical data
- **Multi-Repo Support**: Configurable target repositories

## Workflow

1. **Security Bot** → Runs scanners, generates findings
2. **Architect Bot** → Creates implementation plan with risk assessment
3. **Engineer Bot** → Opens PRs for allowlisted paths (tests/, docs/, reports/, deps/)
4. **Metrics Collector** → Tracks performance and trends

## Quick Start

### Local Setup

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install security scanners (macOS)
brew install trivy gitleaks

# Run orchestrator
python3 orchestrator/main.py
```

For Linux installation, see [Security Scanning Runbook](docs/runbooks/security_scanning.md).

### Configuration

Edit `orchestrator/config.json` to:
- Enable/disable specific scanners
- Configure target repositories
- Toggle dry-run mode
- Set GitHub integration (when ready)

## Artifacts Generated

- `reports/security/daily_report.txt` - Human-readable scan summary
- `reports/security/findings.json` - Machine-readable findings
- `reports/security/python_vulns.json` - pip-audit output
- `reports/security/trivy.json` - Trivy scan results
- `reports/security/secrets.json` - Gitleaks findings
- `plans/implementation/plan.json` - Architect's implementation plan
- `audit/logs/last_pr.json` - Last PR created (or `needs_approval.json`)
- `metrics/kpis.json` - Current KPI summary
- `metrics/history.jsonl` - Historical run data

## Guardrails

**Self-Merge Allowlist**: `tests/`, `docs/`, `reports/`, `scripts/audit/`, `deps/`
**Restricted Paths**: `src/`, `infra/`, `db/`, `prod_config/` (require approval)

Every PR includes:
- Tests added/updated
- Rollback plan
- Risk label
- Changelog entry

## Next Steps (Phase 3)

- [ ] Activate idle test_writer for coverage improvements
- [ ] Add SRE sentinel for CI flake monitoring
- [ ] Enable GitHub App for automated PR creation
- [ ] Integrate business KPI monitoring (opt-in)
