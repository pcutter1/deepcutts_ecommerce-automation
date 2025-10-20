import json, time
from pathlib import Path
from fnmatch import fnmatch

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT/'orchestrator/policy.json').read_text())

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
    report = (
        f"DATE: {time.strftime('%Y-%m-%d')}\n"
        "SCA: 0 HIGH, 1 MEDIUM\n"
        "SAST: 0 HIGH\n"
        "SECRETS: none\n"
        "IAC: 0 WARN\n"
        "CONTAINER: base image behind: node:20.x (+1 patch)\n"
        "LOG OBS: none abnormal\n"
        "RECOMMENDATIONS:\n"
        "- Bump node base image to latest patch\n"
    )
    write(ROOT/'reports/security/daily_report.txt', report)
    findings = {
        "actions": [{
            "id": "DEP-1",
            "type": "deps_patch",
            "files": ["deps/node_base.txt"],
            "risk": "low",
            "tests": ["build image", "smoke tests"]
        }]
    }
    write(ROOT/'reports/security/findings.json', findings, is_json=True)

def run_architect_bot():
    plan = {
        "objective": "Apply low-risk dependency patch",
        "steps": [{
            "id": "DEP-1",
            "title": "Bump node base image patch",
            "changes": ["deps/node_base.txt"],
            "tests": ["build image", "smoke tests"],
            "rollback": "revert previous image tag",
            "risk": "low",
            "est_hours": 0.5
        }],
        "merge_policy": {
            "self_merge": ["DEP-1"],
            "approval_required": []
        }
    }
    write(ROOT/'plans/implementation/plan.json', plan, is_json=True)

def run_engineer_bot():
    plan = json.loads((ROOT/'plans/implementation/plan.json').read_text())
    step = plan['steps'][0]
    changed = step['changes']
    if gate_changes(changed):
        pr_stub = {
            "title": step['title'],
            "files": changed,
            "status": "draft",
            "requires": POLICY['must_include_in_pr']
        }
        write(ROOT/'audit/logs/last_pr.json', pr_stub, is_json=True)
        return True
    else:
        write(ROOT/'audit/logs/needs_approval.json', {"files": changed}, is_json=True)
        return False

if __name__ == "__main__":
    run_security_bot()
    run_architect_bot()
    ok = run_engineer_bot()
    print("SELF-MERGE-ELIGIBLE" if ok else "APPROVAL-REQUIRED")
