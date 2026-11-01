from __future__ import annotations

import datetime as dt
import json

from conftest import cluster_by

from secubot.config import SecfixConfig, Suppression
from secubot.models import Kind
from secubot.state import (
    IssueRef,
    PullRef,
    RepoState,
    dump_state_suppressions,
    parse_state_suppressions,
    select,
    suppression_matches,
)

NOW = dt.datetime(2026, 11, 1, tzinfo=dt.UTC)


def _cfg(**policy) -> SecfixConfig:
    return SecfixConfig.model_validate({"policy": {"max_triage": 50, **policy}})


def test_default_selection(report):
    sel = select(report, RepoState(), _cfg(), NOW)
    chosen = {report.cluster(cid).kind for cid in sel.selected}
    assert Kind.CODE in chosen
    reasons = {d.cluster_id: d.reason for d in sel.decisions}
    stdlib = cluster_by(report, package="stdlib")
    assert "below policy.min_severity" in reasons[stdlib.id]
    # non-breaking bumps are left to Dependabot/Renovate, breaking + reachable taken
    requests = cluster_by(report, package="requests")
    assert "Renovate/Dependabot" in reasons[requests.id]
    xtext = cluster_by(report, package="golang.org/x/text")
    assert xtext.id in sel.selected


def test_cap_ranks_by_severity_then_reachability(report):
    sel = select(report, RepoState(), _cfg(max_triage=2), NOW)
    assert len(sel.selected) == 2
    first = report.cluster(sel.selected[0])
    assert first.severity.value == "high"
    assert any("max_triage" in d.reason for d in sel.decisions)


def test_in_flight_and_cooldown(report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    other = cluster_by(report, path="goapp/main.go", line=24)
    shell = cluster_by(report, path="pyapp/app.py", line=13)
    xtext = cluster_by(report, package="golang.org/x/text")
    state = RepoState(
        branches={c.branch},
        pulls=[
            PullRef(
                number=1, head=other.branch, state="CLOSED", closed_at=NOW - dt.timedelta(days=10)
            )
        ],
        issues=[IssueRef(number=2, title=f"[secfix:{shell.id}] x", state="OPEN")],
    )
    sel = select(report, state, _cfg(), NOW)
    reasons = {d.cluster_id: d.reason for d in sel.decisions}
    assert "already exists" in reasons[c.id]
    assert "closed without merge" in reasons[other.id]
    assert reasons[shell.id] == "open issue"
    assert xtext.id in sel.selected
    # once the cool-down has passed, the finding comes back
    later = select(report, RepoState(pulls=state.pulls), _cfg(), NOW + dt.timedelta(days=100))
    assert other.id in later.selected


def test_suppressions(report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    today = NOW.date()
    by_rule = Suppression(
        rule="cwe-78",
        path="goapp/**",
        reason="test fixture only",
        expires=today + dt.timedelta(days=1),
    )
    assert suppression_matches(by_rule, c)
    expired = Suppression(
        id=c.id, reason="expired suppression", expires=today - dt.timedelta(days=1)
    )
    cfg = _cfg()
    cfg.suppressions = [expired]
    sel = select(report, RepoState(), cfg, NOW)
    assert c.id in sel.selected and expired in sel.expired_suppressions
    cfg.suppressions = [by_rule]
    sel = select(report, RepoState(), cfg, NOW)
    assert c.id not in sel.selected


def test_state_suppressions_roundtrip():
    items = [
        Suppression(
            id="abc123abc123",
            reason="false positive: constant input",
            expires=dt.date(2027, 1, 1),
            source="triage",
        )
    ]
    text = dump_state_suppressions(items)
    assert text.startswith("# Managed by secubot")
    assert parse_state_suppressions(text) == items
    assert parse_state_suppressions(":: not yaml [") == []
    assert parse_state_suppressions("suppressions: [{reason: short}]") == []


def test_repo_state_load(tmp_path):
    (tmp_path / "branches.json").write_text(json.dumps(["refs/heads/secfix/aaaaaaaaaaaa"]))
    (tmp_path / "pulls.json").write_text(
        json.dumps(
            [
                {
                    "number": 3,
                    "headRefName": "secfix/bbbbbbbbbbbb",
                    "state": "CLOSED",
                    "closedAt": "2026-10-01T00:00:00Z",
                    "mergedAt": "2026-10-01T00:00:00Z",
                    "url": "u",
                }
            ]
        )
    )
    (tmp_path / "issues.json").write_text(
        json.dumps([{"number": 4, "title": "[secfix:cccccccccccc] t", "state": "open", "url": "u"}])
    )
    state = RepoState.load(tmp_path)
    assert state.branches == {"secfix/aaaaaaaaaaaa"}
    assert state.pulls[0].state == "MERGED"
    assert state.issues[0].cluster_id == "cccccccccccc"
    assert RepoState.load(tmp_path / "missing").branches == set()


def test_clusters_only_in_protected_paths_are_report_only(report, cfg):
    import copy

    from secubot.state import RepoState, select

    rep = copy.deepcopy(report)
    target = rep.clusters[0]
    for f in target.findings:
        f.path = ".github/workflows/release.yml"
    sel = select(rep, RepoState(), cfg)
    decision = next(d for d in sel.decisions if d.cluster_id == target.id)
    assert not decision.selected and "protected path" in decision.reason
