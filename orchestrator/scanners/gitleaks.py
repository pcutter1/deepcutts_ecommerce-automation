"""
Gitleaks scanner integration

Detects accidentally committed secrets and credentials.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional
from . import ScannerResult


def scan(repo_path: Optional[Path] = None) -> ScannerResult:
    """
    Run gitleaks on the repository

    Args:
        repo_path: Path to repository root (defaults to current dir)

    Returns:
        ScannerResult with normalized findings
    """
    result = ScannerResult("gitleaks")

    if repo_path is None:
        repo_path = Path.cwd()

    output_path = repo_path / "reports/security/secrets.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Run gitleaks
        cmd = [
            "gitleaks", "detect",
            "--report-format", "json",
            "--report-path", str(output_path),
            "--no-git"  # Scan current state, not git history
        ]
        proc = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, timeout=300)

        # gitleaks exits with code 1 if secrets found, which is expected
        if proc.returncode not in [0, 1]:
            print(f"gitleaks warning: exit code {proc.returncode}")
            print(f"stderr: {proc.stderr}")

        # Parse output
        if output_path.exists() and output_path.stat().st_size > 0:
            with open(output_path) as f:
                try:
                    data = json.load(f)

                    # Gitleaks format: array of findings
                    if isinstance(data, list):
                        for secret in data:
                            result.add_finding({
                                "id": f"GITLEAKS-{secret.get('RuleID', 'UNKNOWN')}",
                                "type": "secret",
                                "scanner": "gitleaks",
                                "severity": "CRITICAL",  # All secrets are critical
                                "description": f"{secret.get('File', 'unknown')}:{secret.get('StartLine', '?')}: {secret.get('Description', 'Secret detected')}",
                                "secret_type": secret.get("RuleID"),
                                "files": [secret.get("File", "unknown")],
                                "line": secret.get("StartLine"),
                                "recommended_tests": [
                                    "rotate credentials immediately",
                                    "audit access logs",
                                    "verify no unauthorized access"
                                ]
                            })
                except json.JSONDecodeError:
                    print("gitleaks output is not valid JSON")
        else:
            # No secrets found - this is good!
            pass

    except subprocess.TimeoutExpired:
        print("gitleaks timed out after 5 minutes")
    except FileNotFoundError:
        print("gitleaks not found. Install with: brew install gitleaks (macOS) or see docs/runbooks/security_scanning.md")
    except Exception as e:
        print(f"gitleaks error: {e}")

    return result
