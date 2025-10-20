"""
pip-audit scanner integration

Scans Python dependencies for known vulnerabilities using pip-audit.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional
from . import ScannerResult


def scan(repo_path: Optional[Path] = None) -> ScannerResult:
    """
    Run pip-audit on the repository

    Args:
        repo_path: Path to repository root (defaults to current dir)

    Returns:
        ScannerResult with normalized findings
    """
    result = ScannerResult("pip-audit")

    if repo_path is None:
        repo_path = Path.cwd()

    output_path = repo_path / "reports/security/python_vulns.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Run pip-audit
        cmd = ["pip-audit", "--format", "json", "--output", str(output_path)]
        proc = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, timeout=300)

        # pip-audit exits with code 1 if vulnerabilities found, which is expected
        if proc.returncode not in [0, 1]:
            print(f"pip-audit warning: exit code {proc.returncode}")
            print(f"stderr: {proc.stderr}")

        # Parse output
        if output_path.exists():
            with open(output_path) as f:
                data = json.load(f)

            # pip-audit format: {"dependencies": [...]}
            for dep in data.get("dependencies", []):
                package_name = dep.get("name", "unknown")
                package_version = dep.get("version", "unknown")

                for vuln in dep.get("vulns", []):
                    result.add_finding({
                        "id": f"PIP-{vuln.get('id', 'UNKNOWN')}",
                        "type": "dependency_vulnerability",
                        "scanner": "pip-audit",
                        "severity": map_severity(vuln.get("fix_versions", [])),
                        "description": f"{package_name} {package_version}: {vuln.get('description', 'No description')}",
                        "package": package_name,
                        "version": package_version,
                        "cve": vuln.get("id"),
                        "fix_version": vuln.get("fix_versions", [None])[0] if vuln.get("fix_versions") else None,
                        "files": ["requirements.txt", "pyproject.toml"],
                        "recommended_tests": ["pip install --dry-run", "unit tests"]
                    })

    except subprocess.TimeoutExpired:
        print("pip-audit timed out after 5 minutes")
    except FileNotFoundError:
        print("pip-audit not found. Install with: pip install pip-audit")
    except Exception as e:
        print(f"pip-audit error: {e}")

    return result


def map_severity(fix_versions: list) -> str:
    """
    Map pip-audit findings to severity levels

    Since pip-audit doesn't provide severity, we infer:
    - Fix available: MEDIUM
    - No fix: HIGH (requires manual intervention)
    """
    if fix_versions and len(fix_versions) > 0:
        return "MEDIUM"
    return "HIGH"
