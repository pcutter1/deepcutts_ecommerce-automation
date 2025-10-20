"""
Security scanners module for agentic automation.

Provides a unified interface for running various security scanners
and normalizing their outputs into a common format.
"""

from pathlib import Path
from typing import List, Dict, Any
import json

class ScannerResult:
    """Normalized scanner result format"""

    def __init__(self, scanner_name: str):
        self.scanner_name = scanner_name
        self.findings: List[Dict[str, Any]] = []
        self.summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0
        }

    def add_finding(self, finding: Dict[str, Any]):
        """Add a normalized finding"""
        self.findings.append(finding)
        severity = finding.get("severity", "UNKNOWN").lower()
        if severity in self.summary:
            self.summary[severity] += 1
        self.summary["total"] += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner_name,
            "summary": self.summary,
            "findings": self.findings
        }


def aggregate_results(results: List[ScannerResult]) -> Dict[str, Any]:
    """
    Aggregate multiple scanner results into a unified findings.json format

    Returns:
        {
            "summary": {"critical": N, "high": N, ...},
            "scanners": [...],
            "actions": [...]
        }
    """
    total_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    all_findings = []
    actions = []

    for result in results:
        for key in total_summary:
            total_summary[key] += result.summary.get(key, 0)
        all_findings.extend(result.findings)

    # Convert findings to actions
    for finding in all_findings:
        if finding.get("severity") in ["CRITICAL", "HIGH"]:
            actions.append({
                "id": finding.get("id", "UNKNOWN"),
                "type": finding.get("type", "vulnerability"),
                "description": finding.get("description", ""),
                "files": finding.get("files", []),
                "risk": finding.get("severity", "UNKNOWN").lower(),
                "tests": finding.get("recommended_tests", [])
            })

    return {
        "summary": total_summary,
        "scanners": [r.to_dict() for r in results],
        "actions": actions
    }
