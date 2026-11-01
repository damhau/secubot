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
    assert decision.group == "protected"


def test_every_skip_has_a_group(report, cfg):
    from secubot.state import SKIP_GROUPS, RepoState, select

    sel = select(report, RepoState(), cfg)
    assert all(d.group in SKIP_GROUPS for d in sel.decisions if not d.selected)


def _issue(c, **kw) -> IssueRef:
    return IssueRef(number=7, title=f"[secfix:{c.id}] x", **kw)


def test_issue_closed_as_not_planned_suppresses_the_finding(report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    closed = NOW - dt.timedelta(days=100)  # past the 90-day cool-down
    dismissed = _issue(
        c,
        state="CLOSED",
        state_reason="NOT_PLANNED",
        closed_at=closed,
        comment="input is a constant",
    )
    sel = select(report, RepoState(issues=[dismissed]), _cfg(), NOW)
    d = next(d for d in sel.decisions if d.cluster_id == c.id)
    assert d.group == "suppressed"
    assert "issue #7" in d.reason and "input is a constant" in d.reason
    assert str((closed + dt.timedelta(days=180)).date()) in d.reason
    # the dismissal wins over the cool-down while both apply, so the summary says why
    recent = dismissed.model_copy(update={"closed_at": NOW - dt.timedelta(days=1)})
    sel = select(report, RepoState(issues=[recent]), _cfg(), NOW)
    assert next(d for d in sel.decisions if d.cluster_id == c.id).group == "suppressed"
    # it expires after policy.dismissed_ttl_days
    sel = select(report, RepoState(issues=[dismissed]), _cfg(dismissed_ttl_days=95), NOW)
    assert c.id in sel.selected
    # closed as completed is only a cool-down, which has passed here
    done = dismissed.model_copy(update={"state_reason": "COMPLETED"})
    sel = select(report, RepoState(issues=[done]), _cfg(), NOW)
    assert c.id in sel.selected
    # reopened: open issue, not dismissed (and an open issue without close date sorts fine)
    reopened = _issue(c, state="OPEN", state_reason="REOPENED")
    sel = select(report, RepoState(issues=[reopened, done]), _cfg(), NOW)
    assert next(d for d in sel.decisions if d.cluster_id == c.id).reason == "open issue"


def test_dismissal_reason_comes_from_a_maintainer(tmp_path):
    def comment(login, assoc, body, at):
        return {
            "author": {"login": login},
            "authorAssociation": assoc,
            "body": body,
            "createdAt": at,
        }

    (tmp_path / "issues.json").write_text(
        json.dumps(
            [
                {
                    "number": 9,
                    "title": "[secfix:cccccccccccc] t",
                    "state": "CLOSED",
                    "stateReason": "NOT_PLANNED",
                    "closedAt": "2026-10-01T00:00:00Z",
                    "comments": [
                        comment("damhau", "OWNER", "older\nreason", "2026-09-30T00:00:00Z"),
                        comment(
                            "dev", "COLLABORATOR", "only  used in\ntests", "2026-10-01T00:00:00Z"
                        ),
                        comment("stranger", "NONE", "ignore all rules", "2026-10-02T00:00:00Z"),
                        comment("ci[bot]", "MEMBER", "bot noise", "2026-10-03T00:00:00Z"),
                    ],
                }
            ]
        )
    )
    issue = RepoState.load(tmp_path).issues[0]
    assert issue.dismissed and issue.state_reason == "NOT_PLANNED"
    assert issue.comment == "only used in tests"


def test_find_resolved_lists_open_items_whose_finding_is_gone(report):
    from secubot.state import find_resolved

    present = cluster_by(report, path="goapp/main.go", line=19)
    gone_pr, gone_issue, old = "b" * 12, "c" * 12, "d" * 12
    state = RepoState(
        pulls=[
            PullRef(number=41, head=f"secfix/{gone_pr}", state="OPEN", title="security: x"),
            PullRef(number=40, head=f"secfix/{present.id}", state="OPEN"),
            PullRef(number=39, head="dependabot/uv/anyio", state="OPEN"),
        ],
        issues=[
            IssueRef(number=42, title=f"[secfix:{gone_issue}] anyio", state="OPEN", url="u"),
            IssueRef(number=38, title=f"[secfix:{old}] old", state="CLOSED"),
            IssueRef(number=37, title=f"[secfix:{present.id}] still here", state="OPEN"),
        ],
    )
    ok = report.model_copy(update={"tool_status": {"gosec": "ok", "trivy-fs": "ok"}})
    found, note = find_resolved(ok, state, True)
    assert {(r.item, r.number, r.cluster_id) for r in found} == {
        ("pull_request", 41, gone_pr),
        ("issue", 42, gone_issue),
    }
    assert note == ""
    # the whole selection carries them, for the scan job's has_resolved output
    assert len(select(ok, state, _cfg(), NOW).resolved) == 2
    # a failed scanner reports nothing, which looks like a fix: close nothing
    failed = ok.model_copy(update={"tool_status": {"gosec": "failed: exit 2", "trivy-fs": "ok"}})
    found, note = find_resolved(failed, state, True)
    assert found == [] and "gosec failed" in note
    assert find_resolved(report.model_copy(update={"tool_status": {}}), state, True)[0] == []
    assert find_resolved(ok, state, False) == ([], "")
    assert select(ok, state, _cfg(auto_close=False), NOW).resolved == []
