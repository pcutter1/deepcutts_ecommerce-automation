import json, time, logging, sys
from pathlib import Path
from fnmatch import fnmatch
from datetime import datetime

# Add parent directory to path for imports
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Import scanner modules
from orchestrator.scanners import pip_audit, trivy, gitleaks, aggregate_results
from orchestrator.metrics_collector import MetricsCollector
from orchestrator.github_client import GitHubClient

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

POLICY = json.loads((ROOT/'orchestrator/policy.json').read_text())
CONFIG = json.loads((ROOT/'orchestrator/config.json').read_text())

def write(p: Path, s: str, is_json=False):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(s, indent=2) if is_json else s)

def anymatch(patterns, path):
    return any(fnmatch(path, pat) for pat in patterns)

def gate_changes(changed_paths):
    safe = all(anymatch(POLICY['self_merge_paths'], p) for p in changed_paths)
    restricted = any(anymatch(POLICY['restricted_paths'], p) for p in changed_paths)
    return (safe and not restricted)

def run_security_bot():
    """
    Run all enabled security scanners and aggregate results
    """
    logger.info("Running security scanners...")
    start_time = time.time()

    scanner_results = []

    # Run pip-audit
    if CONFIG.get("scanners", {}).get("pip-audit", {}).get("enabled", True):
        logger.info("  - Running pip-audit...")
        try:
            result = pip_audit.scan(ROOT)
            scanner_results.append(result)
            logger.info(f"    Found {result.summary['total']} issues")
        except Exception as e:
            logger.error(f"    pip-audit failed: {e}")

    # Run trivy
    if CONFIG.get("scanners", {}).get("trivy", {}).get("enabled", True):
        logger.info("  - Running trivy...")
        try:
            result = trivy.scan(ROOT)
            scanner_results.append(result)
            logger.info(f"    Found {result.summary['total']} issues")
        except Exception as e:
            logger.error(f"    trivy failed: {e}")

    # Run gitleaks
    if CONFIG.get("scanners", {}).get("gitleaks", {}).get("enabled", True):
        logger.info("  - Running gitleaks...")
        try:
            result = gitleaks.scan(ROOT)
            scanner_results.append(result)
            logger.info(f"    Found {result.summary['total']} secrets")
        except Exception as e:
            logger.error(f"    gitleaks failed: {e}")

    # Aggregate results
    findings = aggregate_results(scanner_results)

    # Write findings.json
    write(ROOT/'reports/security/findings.json', findings, is_json=True)

    # Generate human-readable report
    report = generate_daily_report(findings)
    write(ROOT/'reports/security/daily_report.txt', report)

    duration = time.time() - start_time
    logger.info(f"Security scan completed in {duration:.1f}s")

    return scanner_results, duration

def generate_daily_report(findings: dict) -> str:
    """Generate human-readable security report"""
    summary = findings.get("summary", {})

    report = f"""DATE: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

SUMMARY
-------
Total Findings: {summary.get('total', 0)}
  CRITICAL: {summary.get('critical', 0)}
  HIGH:     {summary.get('high', 0)}
  MEDIUM:   {summary.get('medium', 0)}
  LOW:      {summary.get('low', 0)}

SCANNERS RUN
------------
"""

    for scanner in findings.get("scanners", []):
        scanner_name = scanner.get("scanner", "unknown")
        scanner_summary = scanner.get("summary", {})
        report += f"- {scanner_name}: {scanner_summary.get('total', 0)} findings\n"

    report += "\nACTIONS RECOMMENDED\n-------------------\n"

    actions = findings.get("actions", [])
    if not actions:
        report += "No high-priority actions required.\n"
    else:
        for action in actions[:10]:  # Show top 10
            report += f"- [{action.get('risk', 'unknown').upper()}] {action.get('description', 'No description')}\n"

        if len(actions) > 10:
            report += f"\n... and {len(actions) - 10} more. See findings.json for details.\n"

    return report

def run_architect_bot():
    """
    Analyze findings and create implementation plan
    """
    logger.info("Running architect bot...")

    findings = json.loads((ROOT/'reports/security/findings.json').read_text())
    actions = findings.get("actions", [])

    if not actions:
        logger.info("  No actions to plan")
        plan = {
            "objective": "No security issues found",
            "steps": [],
            "merge_policy": {
                "self_merge": [],
                "approval_required": []
            }
        }
        write(ROOT/'plans/implementation/plan.json', plan, is_json=True)
        return

    # Take first action for now (future: prioritize and batch)
    action = actions[0]

    plan = {
        "objective": action.get("description", "Address security finding"),
        "steps": [{
            "id": action.get("id", "ACTION-1"),
            "title": f"Fix {action.get('id', 'security issue')}",
            "changes": action.get("files", []),
            "tests": action.get("tests", ["verify fix", "run tests"]),
            "rollback": "revert commit",
            "risk": action.get("risk", "medium"),
            "est_hours": 1.0
        }],
        "merge_policy": {
            "self_merge": [action.get("id")] if action.get("risk") == "low" else [],
            "approval_required": [] if action.get("risk") == "low" else [action.get("id")]
        }
    }

    write(ROOT/'plans/implementation/plan.json', plan, is_json=True)
    logger.info(f"  Created plan: {plan['objective']}")

def run_engineer_bot():
    """
    Create PR for approved changes (or stub if GitHub disabled)
    """
    logger.info("Running engineer bot...")

    plan = json.loads((ROOT/'plans/implementation/plan.json').read_text())

    if not plan.get("steps"):
        logger.info("  No steps in plan, skipping")
        return False

    step = plan['steps'][0]
    changed = step['changes']

    if not changed:
        logger.info("  No files to change, skipping")
        return False

    # Check gate
    self_merge_eligible = gate_changes(changed)

    if self_merge_eligible:
        logger.info("  Changes are self-merge eligible")

        # Create PR if GitHub enabled
        github_client = GitHubClient(CONFIG, dry_run=CONFIG.get("orchestrator", {}).get("dry_run", False))

        if github_client.enabled:
            pr_body = github_client.format_pr_body(
                objective=step['title'],
                changes=step['changes'],
                tests=step['tests'],
                rollback=step['rollback'],
                risk=step['risk']
            )

            branch_name = f"automation/{step['id'].lower()}-{int(time.time())}"
            pr_url = github_client.create_pr(
                branch_name=branch_name,
                title=step['title'],
                body=pr_body,
                files=step['changes'],
                labels=[f"risk:{step['risk']}", "automation"]
            )

            pr_stub = {
                "title": step['title'],
                "files": changed,
                "status": "created" if pr_url else "failed",
                "pr_url": pr_url,
                "requires": POLICY['must_include_in_pr']
            }
        else:
            pr_stub = {
                "title": step['title'],
                "files": changed,
                "status": "draft",
                "requires": POLICY['must_include_in_pr']
            }

        write(ROOT/'audit/logs/last_pr.json', pr_stub, is_json=True)
        return True
    else:
        logger.info("  Changes require approval (restricted paths)")
        write(ROOT/'audit/logs/needs_approval.json', {"files": changed, "reason": "restricted paths"}, is_json=True)
        return False

def main():
    """Main orchestrator entry point"""
    logger.info("=== Agentic Automation Orchestrator ===")
    logger.info(f"Run started at {datetime.utcnow().isoformat()}Z")

    overall_start = time.time()

    try:
        # Step 1: Security scanning
        scanner_results, scan_duration = run_security_bot()

        # Step 2: Architecture planning
        run_architect_bot()

        # Step 3: Engineering (PR creation)
        self_merge_eligible = run_engineer_bot()

        # Step 4: Metrics collection
        metrics = MetricsCollector(ROOT)
        metrics.record_run(
            scan_results=[r.to_dict() for r in scanner_results],
            pr_created=False,  # Will be True when GitHub integration enabled
            self_merge_eligible=self_merge_eligible,
            duration_seconds=time.time() - overall_start
        )

        # Print summary
        total_duration = time.time() - overall_start
        logger.info(f"=== Run completed in {total_duration:.1f}s ===")
        print("SELF-MERGE-ELIGIBLE" if self_merge_eligible else "APPROVAL-REQUIRED")

    except Exception as e:
        logger.error(f"Orchestrator failed: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
