"""Machine-readable run report (`secubot-report` artifact), consumed by the control plane."""

from __future__ import annotations

import datetime as dt
import os

from secubot import __version__
from secubot.fix import FixResult
from secubot.models import ScanReport
from secubot.normalise import severity_counts
from secubot.state import Selection
from secubot.triage import TriageResult

REPORT_SCHEMA = 1


def fleet_entry(
    report: ScanReport,
    selection: Selection | None,
    triage: dict[str, TriageResult],
    fixes: dict[str, FixResult],
    actions: list[dict],
) -> dict:
    return {
        "schema": REPORT_SCHEMA,
        "secubot": __version__,
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_url": (
            f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
            f"{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/"
            f"{os.environ.get('GITHUB_RUN_ID', '')}"
        ),
        "base_sha": report.base_sha,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "tool_status": report.tool_status,
        "totals": {
            "raw_results": report.raw_results,
            "findings": len(report.findings),
            "clusters": len(report.clusters),
            "by_severity": severity_counts(report.clusters),
            "selected": len(selection.selected) if selection else 0,
        },
        "triage": {
            cid: {"action": t.action, "verdict": t.final_verdict, "cost_usd": t.cost_usd}
            for cid, t in triage.items()
        },
        "fixes": {
            cid: {"status": f.status, "attempts": len(f.attempts), "cost_usd": f.cost_usd}
            for cid, f in fixes.items()
        },
        "cost_usd": round(
            sum(t.cost_usd for t in triage.values()) + sum(f.cost_usd for f in fixes.values()), 4
        ),
        "actions": actions,
    }
