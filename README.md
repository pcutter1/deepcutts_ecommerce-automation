# Agentic Automation (Phase 1)

Autonomous bots for security + CI hygiene under human-approved guardrails. Business metrics hooks are stubbed but disabled.
- Orchestrator drives daily cadence and approvals
- Security bot → Architect bot → Engineer bot PRs
- Deps + tests improve continuously when idle

## Run locally

```bash
python3 orchestrator/main.py
```

## Artifacts
- `reports/security/daily_report.txt`
- `reports/security/findings.json`
- `plans/implementation/plan.json`
- `audit/logs/last_pr.json` (or `needs_approval.json`)
