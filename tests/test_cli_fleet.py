from __future__ import annotations

import datetime as dt
import json
import subprocess

import pytest
from conftest import prepare_sarif

from secubot.cli import main
from secubot.fleet import (
    Fleet,
    FleetRepo,
    current_slot,
    dispatch,
    render_dashboard,
    slot_of,
    unhealthy,
)
from secubot.triage import TriageResult


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
    assert run_report["totals"]["clusters"] == 14 and run_report["schema"] == 1


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


def _scan(project, tmp_path, monkeypatch):
    """A scan directory with real findings selected for triage."""
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "gh_output"))
    scan = tmp_path / "scan"
    sarif = scan / "sarif"
    prepare_sarif(project, sarif)
    (sarif / "status.json").write_text(json.dumps({"gosec": "ok"}))
    report, selection = str(scan / "report.json"), str(scan / "selection.json")
    args = ["--repo", str(project)]
    assert main(["normalise", *args, "--sarif-dir", str(sarif), "--out", report]) == 0
    assert main(["select", *args, "--report", report, "--out", selection]) == 0
    selected = json.loads((scan / "selection.json").read_text())["selected"]
    assert len(selected) > 1
    return scan, selected


@pytest.mark.parametrize(
    ("good", "expected"),
    [(0, 1), (1, 0)],
    ids=["every finding errors", "one finding still triaged"],
)
def test_triage_fails_only_when_every_finding_errors(
    project, tmp_path, monkeypatch, capsys, good, expected
):
    scan, selected = _scan(project, tmp_path, monkeypatch)
    keep = set(selected[:good])

    async def fake(cluster, cfg, repo, session):
        if cluster.id in keep:
            return TriageResult(cluster_id=cluster.id, action="issue", reason="real")
        return TriageResult(cluster_id=cluster.id, action="error", reason="x", error="bad key")

    monkeypatch.setattr("secubot.triage.triage_cluster", fake)
    out = tmp_path / "triage"
    assert (
        main(["triage", "--repo", str(project), "--scan-dir", str(scan), "--out", str(out)])
        == expected
    )
    # the report job and the dashboard read this, whatever the exit code
    assert len(json.loads((out / "triage.json").read_text())) == len(selected)
    assert ("bad key" in capsys.readouterr().err) is bool(expected)


def test_triage_with_nothing_selected_succeeds(project, tmp_path, monkeypatch):
    scan, _ = _scan(project, tmp_path, monkeypatch)
    selection = json.loads((scan / "selection.json").read_text())
    (scan / "selection.json").write_text(json.dumps({**selection, "selected": []}))
    out = tmp_path / "triage"
    args = ["triage", "--repo", str(project), "--scan-dir", str(scan), "--out", str(out)]
    assert main(args) == 0


@pytest.mark.parametrize(("failing", "expected"), [(set(), 0), ({"org/a"}, 1)])
def test_fleet_dispatch_exit_code(tmp_path, monkeypatch, capsys, failing, expected):
    fleet = tmp_path / "fleet.yml"
    fleet.write_text("delay_seconds: 0\nrepos:\n  - repo: org/a\n  - repo: org/b\n")
    seen = []

    def fake_gh(*args, check=True):
        repo = args[args.index("--repo") + 1]
        seen.append(repo)
        return subprocess.CompletedProcess(args, 1 if repo in failing else 0, "", "HTTP 404")

    monkeypatch.setattr("secubot.fleet._gh", fake_gh)
    assert main(["fleet-dispatch", "--fleet", str(fleet), "--all"]) == expected
    assert seen == ["org/a", "org/b"]  # one failure doesn't stop the others
    assert ("FAILED" in capsys.readouterr().out) is bool(expected)


def test_dashboard_flags_triage_errors():
    triage = {"a": {"action": "error"}, "b": {"action": "issue"}}
    entry = {"repository": "org/a", "conclusion": "success", "report": {"triage": triage}}
    assert "triage failed: 1 of 2" in render_dashboard([entry])


@pytest.mark.parametrize(
    "entry",
    [
        {"conclusion": "failure", "report": {}},
        {"conclusion": "success", "report": {"tool_status": {"gosec": "failed: x"}}},
        {"conclusion": "success", "report": {"triage": {"a": {"action": "error"}}}},
        {"error": "no completed run"},
    ],
)
def test_unhealthy(entry):
    healthy = {
        "repository": "org/ok",
        "conclusion": "success",
        "report": {"tool_status": {"gosec": "ok"}, "triage": {"a": {"action": "issue"}}},
    }
    assert unhealthy([healthy, {"repository": "org/bad", **entry}]) == ["org/bad"]


@pytest.mark.parametrize(("conclusion", "expected"), [("success", 0), ("failure", 1)])
def test_fleet_report_exit_code(tmp_path, monkeypatch, capsys, conclusion, expected):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    fleet = tmp_path / "fleet.yml"
    fleet.write_text("repos:\n  - repo: org/a\n")
    out = tmp_path / "dashboard"
    out.mkdir()
    entries = [{"repository": "org/a", "conclusion": conclusion, "report": {}}]
    monkeypatch.setattr("secubot.fleet.collect", lambda fleet, out_dir: entries)
    assert main(["fleet-report", "--fleet", str(fleet), "--out", str(out)]) == expected
    assert (out / "dashboard.md").is_file() and (out / "fleet.json").is_file()
    assert ("org/a" in capsys.readouterr().err) is bool(expected)
