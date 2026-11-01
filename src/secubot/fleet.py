"""Optional control plane: dispatch staggered runs across a fleet and collect run reports.

Runs with a GitHub App installation token that has `actions: write` (dispatch, and read
run artifacts) and nothing else. The scans themselves still run in each target repository
with that repository's own GITHUB_TOKEN.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import subprocess
import time
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

REPO_RE = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"


class FleetRepo(BaseModel, extra="forbid"):
    repo: str = Field(pattern=REPO_RE)
    ref: str | None = None
    workflow: str | None = None
    enabled: bool = True
    inputs: dict[str, str] = Field(default_factory=dict)


class Fleet(BaseModel, extra="forbid"):
    workflow: str = "secfix.yml"
    """Caller workflow file name in each target repository."""
    ref: str = "main"
    slots: int = Field(default=24, ge=1, le=168)
    """Spread repositories over this many slots; the control plane runs once per slot (e.g.
    hourly cron with 24 slots = each repository once a day, at its own hour)."""
    delay_seconds: float = Field(default=2.0, ge=0, le=60)
    report_artifact: str = "secubot*-report"
    """Artifact name pattern (monorepo instances upload secubot-<name>-report)."""
    repos: list[FleetRepo]

    @field_validator("repos")
    @classmethod
    def _unique(cls, v: list[FleetRepo]) -> list[FleetRepo]:
        names = [r.repo.lower() for r in v]
        if len(names) != len(set(names)):
            raise ValueError("duplicate repositories in fleet")
        return v


def load_fleet(path: Path) -> Fleet:
    return Fleet.model_validate(yaml.safe_load(path.read_text()) or {})


def slot_of(repo: str, slots: int) -> int:
    return int(hashlib.sha256(repo.lower().encode()).hexdigest(), 16) % slots


def current_slot(now: dt.datetime, slots: int) -> int:
    hours = int(now.timestamp() // 3600)
    return hours % slots


def _gh(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])}: {proc.stderr.strip()[-400:]}")
    return proc


def dispatch(
    fleet: Fleet,
    now: dt.datetime,
    dispatch_all: bool = False,
    dry_run: bool = False,
    only: str | None = None,
) -> list[str]:
    slot = current_slot(now, fleet.slots)
    done = []
    for r in fleet.repos:
        if not r.enabled or (only and r.repo.lower() != only.lower()):
            continue
        if not dispatch_all and not only and slot_of(r.repo, fleet.slots) != slot:
            continue
        args = [
            "workflow",
            "run",
            r.workflow or fleet.workflow,
            "--repo",
            r.repo,
            "--ref",
            r.ref or fleet.ref,
        ]
        for k, v in sorted(r.inputs.items()):
            args += ["-f", f"{k}={v}"]
        if dry_run:
            done.append("[dry-run] gh " + " ".join(args))
            continue
        proc = _gh(*args, check=False)
        status = "dispatched" if proc.returncode == 0 else f"FAILED: {proc.stderr.strip()[-200:]}"
        done.append(f"{r.repo}: {status}")
        time.sleep(fleet.delay_seconds)
    if not done:
        done.append(f"no repositories in slot {slot}/{fleet.slots}")
    return done


def collect(fleet: Fleet, out_dir: Path) -> list[dict]:
    """Download the latest run report(s) of each repository's secfix workflow."""
    entries: list[dict] = []
    for r in fleet.repos:
        if r.enabled:
            entries.extend(_collect_repo(fleet, r, out_dir))
    return entries


def _collect_repo(fleet: Fleet, r: FleetRepo, out_dir: Path) -> list[dict]:
    base: dict = {"repository": r.repo}
    try:
        runs = json.loads(
            _gh(
                "run",
                "list",
                "--repo",
                r.repo,
                "--workflow",
                r.workflow or fleet.workflow,
                "--limit",
                "1",
                "--status",
                "completed",
                "--json",
                "databaseId,conclusion,createdAt,url",
            ).stdout
            or "[]"
        )
    except (RuntimeError, json.JSONDecodeError) as exc:
        return [{**base, "error": str(exc)[:300]}]
    if not runs:
        return [{**base, "error": "no completed run"}]
    run = runs[0]
    base.update(run_url=run["url"], conclusion=run["conclusion"], created_at=run["createdAt"])
    dest = out_dir / "reports" / r.repo.replace("/", "__")
    dest.mkdir(parents=True, exist_ok=True)
    _gh(
        "run",
        "download",
        str(run["databaseId"]),
        "--repo",
        r.repo,
        "-p",
        fleet.report_artifact,
        "-D",
        str(dest),
        check=False,
    )
    report_files = sorted(dest.glob("**/run-report.json"))
    if not report_files:
        return [{**base, "error": "run report artifact not found"}]
    entries = []
    for report_file in report_files:
        entry = {**base}
        try:
            entry["report"] = json.loads(report_file.read_text())
        except json.JSONDecodeError:
            entry["error"] = "unreadable run report"
        if len(report_files) > 1:
            entry["instance"] = report_file.parent.name
        entries.append(entry)
    return entries


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")[:200]


def render_dashboard(entries: list[dict]) -> str:
    out = [
        "# secubot fleet",
        "",
        "| Repository | Last run | Critical | High | Medium | PRs opened | Issues | Cost | Notes |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    total_cost = 0.0
    for e in entries:
        rep = e.get("report") or {}
        sev = (rep.get("totals") or {}).get("by_severity", {})
        actions = rep.get("actions", [])
        prs = sum(1 for a in actions if a.get("type") == "pull_request")
        issues = sum(1 for a in actions if a.get("type") == "issue")
        cost = float(rep.get("cost_usd") or 0)
        total_cost += cost
        failed = [t for t, s in (rep.get("tool_status") or {}).items() if s != "ok"]
        notes = e.get("error") or (f"scanner failed: {', '.join(failed)}" if failed else "")
        last = f"[{e.get('conclusion', '?')}]({e['run_url']})" if e.get("run_url") else "-"
        out.append(
            f"| {_cell(e['repository'] + (' ' + e['instance'] if e.get('instance') else ''))} "
            f"| {last} | {sev.get('critical', '-')} | "
            f"{sev.get('high', '-')} | {sev.get('medium', '-')} | {prs} | {issues} | "
            f"${cost:.2f} | {_cell(notes)} |"
        )
    out += ["", f"Total agent cost of the latest runs: ${total_cost:.2f}"]
    return "\n".join(out)
