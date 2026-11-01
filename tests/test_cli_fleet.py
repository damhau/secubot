from __future__ import annotations

import datetime as dt
import json

from conftest import prepare_sarif

from secubot.cli import main
from secubot.fleet import Fleet, FleetRepo, current_slot, dispatch, render_dashboard, slot_of


def test_pipeline_commands(project, tmp_path, monkeypatch, capsys):
    out = tmp_path / "gh_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert main(["detect", "--repo", str(project), "--github-output"]) == 0
    detected = dict(line.split("=", 1) for line in out.read_text().splitlines())
    assert detected["go"] == "true" and "gosec" in json.loads(detected["tools"])

    sarif = tmp_path / "scan" / "sarif"
    prepare_sarif(project, sarif)
    (sarif / "status.json").write_text(json.dumps({"gosec": "ok"}))
    scan = tmp_path / "scan"
    assert (
        main(
            [
                "normalise",
                "--repo",
                str(project),
                "--sarif-dir",
                str(sarif),
                "--out",
                str(scan / "report.json"),
                "--base-sha",
                "abc",
            ]
        )
        == 0
    )
    assert json.loads((scan / "report.json").read_text())["base_sha"] == "abc"
    assert (
        main(
            [
                "select",
                "--repo",
                str(project),
                "--report",
                str(scan / "report.json"),
                "--out",
                str(scan / "selection.json"),
                "--github-output",
            ]
        )
        == 0
    )
    assert "has_work=true" in out.read_text()
    assert main(["summary", "--scan-dir", str(scan), "--out", str(tmp_path / "r.json")]) == 0
    assert "# secubot" in capsys.readouterr().out
    run_report = json.loads((tmp_path / "r.json").read_text())
    assert run_report["totals"]["clusters"] == 16 and run_report["schema"] == 1


def test_config_check(project, capsys):
    assert main(["config-check", "--repo", str(project)]) == 0
    assert '"languages"' in capsys.readouterr().out


def test_fleet_slots_and_dispatch():
    fleet = Fleet(repos=[FleetRepo(repo=f"org/r{i}") for i in range(50)], slots=24, delay_seconds=0)
    slots = {slot_of(r.repo, 24) for r in fleet.repos}
    assert len(slots) > 10  # spread out
    now = dt.datetime(2026, 11, 1, 5, tzinfo=dt.UTC)
    planned = dispatch(fleet, now, dry_run=True)
    due = [r.repo for r in fleet.repos if slot_of(r.repo, 24) == current_slot(now, 24)]
    assert len([p for p in planned if p.startswith("[dry-run]")]) == len(due)
    everything = dispatch(fleet, now, dispatch_all=True, dry_run=True)
    assert len(everything) == 50 and "--ref main" in everything[0]


def test_dashboard():
    md = render_dashboard(
        [
            {
                "repository": "org/a",
                "run_url": "https://x",
                "conclusion": "success",
                "report": {
                    "totals": {"by_severity": {"critical": 1, "high": 2, "medium": 0}},
                    "actions": [{"type": "pull_request"}, {"type": "issue"}],
                    "cost_usd": 4.2,
                    "tool_status": {"gosec": "failed: x"},
                },
            },
            {"repository": "org/b", "error": "no completed run"},
        ]
    )
    assert "| org/a | [success](https://x) | 1 | 2 | 0 | 1 | 1 | $4.20 |" in md
    assert "no completed run" in md and "$4.20" in md
