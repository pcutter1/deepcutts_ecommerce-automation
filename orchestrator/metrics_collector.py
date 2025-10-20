"""
Metrics collection and tracking for observability

Tracks automation health, scan results, and autonomy metrics over time.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime, timedelta


class MetricsCollector:
    """
    Collect and aggregate metrics for the agentic automation system
    """

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.metrics_file = repo_path / "metrics/kpis.json"
        self.history_file = repo_path / "metrics/history.jsonl"

    def record_run(
        self,
        scan_results: List[Dict[str, Any]],
        pr_created: bool,
        self_merge_eligible: bool,
        duration_seconds: float
    ):
        """
        Record metrics from an orchestrator run

        Args:
            scan_results: List of scanner result dictionaries
            pr_created: Whether a PR was created
            self_merge_eligible: Whether changes were eligible for self-merge
            duration_seconds: How long the run took
        """
        # Calculate summary stats
        total_findings = sum(r.get("summary", {}).get("total", 0) for r in scan_results)
        critical_count = sum(r.get("summary", {}).get("critical", 0) for r in scan_results)
        high_count = sum(r.get("summary", {}).get("high", 0) for r in scan_results)

        # Create run record
        run_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_findings": total_findings,
            "critical": critical_count,
            "high": high_count,
            "pr_created": pr_created,
            "self_merge_eligible": self_merge_eligible,
            "duration_seconds": duration_seconds,
            "scanners_run": [r.get("scanner") for r in scan_results]
        }

        # Append to history
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.history_file, "a") as f:
            f.write(json.dumps(run_record) + "\n")

        # Update KPIs
        self.update_kpis()

    def update_kpis(self):
        """
        Update rolling KPI metrics from historical data
        """
        if not self.history_file.exists():
            return

        # Load history
        history = []
        with open(self.history_file) as f:
            for line in f:
                if line.strip():
                    history.append(json.loads(line))

        if not history:
            return

        # Calculate KPIs
        now = datetime.utcnow()
        last_30_days = [
            r for r in history
            if datetime.fromisoformat(r["timestamp"].rstrip("Z")) > now - timedelta(days=30)
        ]
        last_14_days = [
            r for r in history
            if datetime.fromisoformat(r["timestamp"].rstrip("Z")) > now - timedelta(days=14)
        ]

        kpis = {
            "last_updated": now.isoformat() + "Z",
            "total_runs": len(history),
            "runs_last_30d": len(last_30_days),
            "autonomy_ratio": self._calc_autonomy_ratio(last_30_days),
            "avg_findings_per_run": self._calc_avg(last_30_days, "total_findings"),
            "critical_findings_trend_14d": self._calc_trend(last_14_days, "critical"),
            "avg_run_duration_seconds": self._calc_avg(last_30_days, "duration_seconds"),
            "prs_created_30d": sum(1 for r in last_30_days if r.get("pr_created", False))
        }

        # Write KPIs
        self.metrics_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.metrics_file, "w") as f:
            json.dump(kpis, f, indent=2)

    def _calc_autonomy_ratio(self, records: List[Dict]) -> float:
        """
        Calculate ratio of self-merge eligible changes to total runs

        Higher is better - means more changes are safe to auto-merge
        """
        if not records:
            return 0.0

        eligible = sum(1 for r in records if r.get("self_merge_eligible", False))
        return round(eligible / len(records), 3)

    def _calc_avg(self, records: List[Dict], field: str) -> float:
        """Calculate average of a numeric field"""
        if not records:
            return 0.0

        values = [r.get(field, 0) for r in records if field in r]
        if not values:
            return 0.0

        return round(sum(values) / len(values), 2)

    def _calc_trend(self, records: List[Dict], field: str) -> str:
        """
        Calculate trend direction for a field

        Returns: "increasing", "decreasing", or "stable"
        """
        if len(records) < 2:
            return "stable"

        # Split into first half and second half
        mid = len(records) // 2
        first_half_avg = self._calc_avg(records[:mid], field)
        second_half_avg = self._calc_avg(records[mid:], field)

        if second_half_avg > first_half_avg * 1.1:
            return "increasing"
        elif second_half_avg < first_half_avg * 0.9:
            return "decreasing"
        else:
            return "stable"

    def get_summary(self) -> Dict[str, Any]:
        """Get current KPI summary"""
        if not self.metrics_file.exists():
            return {"status": "no data"}

        with open(self.metrics_file) as f:
            return json.load(f)
