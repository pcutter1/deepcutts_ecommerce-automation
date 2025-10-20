"""
Trivy scanner integration

Comprehensive security scanner for containers, IaC, and filesystem vulnerabilities.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional
from . import ScannerResult


def scan(repo_path: Optional[Path] = None) -> ScannerResult:
    """
    Run Trivy filesystem scan on the repository

    Args:
        repo_path: Path to repository root (defaults to current dir)

    Returns:
        ScannerResult with normalized findings
    """
    result = ScannerResult("trivy")

    if repo_path is None:
        repo_path = Path.cwd()

    output_path = repo_path / "reports/security/trivy.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Run trivy
        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--output", str(output_path),
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            str(repo_path)
        ]
        proc = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, timeout=600)

        if proc.returncode != 0:
            print(f"trivy warning: exit code {proc.returncode}")
            print(f"stderr: {proc.stderr}")

        # Parse output
        if output_path.exists():
            with open(output_path) as f:
                data = json.load(f)

            # Trivy format: {"Results": [...]}
            for scan_result in data.get("Results", []):
                target = scan_result.get("Target", "unknown")
                scan_type = scan_result.get("Type", "unknown")

                for vuln in scan_result.get("Vulnerabilities", []):
                    result.add_finding({
                        "id": f"TRIVY-{vuln.get('VulnerabilityID', 'UNKNOWN')}",
                        "type": map_type(scan_type),
                        "scanner": "trivy",
                        "severity": vuln.get("Severity", "UNKNOWN"),
                        "description": f"{target}: {vuln.get('Title', vuln.get('VulnerabilityID'))}",
                        "package": vuln.get("PkgName", "unknown"),
                        "version": vuln.get("InstalledVersion", "unknown"),
                        "cve": vuln.get("VulnerabilityID"),
                        "fix_version": vuln.get("FixedVersion"),
                        "files": [target],
                        "recommended_tests": infer_tests(scan_type)
                    })

                # Process misconfigurations
                for misconfig in scan_result.get("Misconfigurations", []):
                    result.add_finding({
                        "id": f"TRIVY-{misconfig.get('ID', 'UNKNOWN')}",
                        "type": "misconfiguration",
                        "scanner": "trivy",
                        "severity": misconfig.get("Severity", "UNKNOWN"),
                        "description": f"{target}: {misconfig.get('Title', 'Configuration issue')}",
                        "files": [target],
                        "recommended_tests": ["config validation", "integration tests"]
                    })

                # Process secrets
                for secret in scan_result.get("Secrets", []):
                    result.add_finding({
                        "id": f"TRIVY-SECRET-{secret.get('RuleID', 'UNKNOWN')}",
                        "type": "secret",
                        "scanner": "trivy",
                        "severity": secret.get("Severity", "HIGH"),
                        "description": f"{target}:{secret.get('StartLine', '?')}: {secret.get('Title', 'Secret detected')}",
                        "files": [target],
                        "recommended_tests": ["verify secret rotation", "audit logs"]
                    })

    except subprocess.TimeoutExpired:
        print("trivy timed out after 10 minutes")
    except FileNotFoundError:
        print("trivy not found. Install with: brew install trivy (macOS) or see docs/runbooks/security_scanning.md")
    except Exception as e:
        print(f"trivy error: {e}")

    return result


def map_type(scan_type: str) -> str:
    """Map Trivy scan type to normalized type"""
    type_map = {
        "pip": "dependency_vulnerability",
        "npm": "dependency_vulnerability",
        "go": "dependency_vulnerability",
        "bundler": "dependency_vulnerability",
        "cargo": "dependency_vulnerability",
        "terraform": "iac_misconfiguration",
        "cloudformation": "iac_misconfiguration",
        "kubernetes": "iac_misconfiguration",
        "dockerfile": "container_vulnerability"
    }
    return type_map.get(scan_type.lower(), "vulnerability")


def infer_tests(scan_type: str) -> list:
    """Infer recommended tests based on scan type"""
    if "terraform" in scan_type.lower() or "cloudformation" in scan_type.lower():
        return ["terraform validate", "terraform plan"]
    elif "kubernetes" in scan_type.lower():
        return ["kubectl apply --dry-run", "kubeval"]
    elif "dockerfile" in scan_type.lower():
        return ["docker build", "container scan"]
    else:
        return ["build", "unit tests"]
