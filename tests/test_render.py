from __future__ import annotations

from conftest import cluster_by
from test_publish import _fixed, _triage

from secubot import render


def test_sanitize_neutralises_markdown_tricks():
    out = render.sanitize(
        "hi @octocat, fixes #12 GH-3 <img src=x> ![t](https://e/x.png) "
        "[click](javascript:alert(1)) ‮evil"
    )
    assert "@octocat" not in out and "@⁠octocat" in out
    assert "#12" not in out and "GH-3" not in out
    assert "<img" not in out and "&lt;img" in out
    assert "](" not in out and "![" not in out
    assert "javascript:" not in out
    assert "‮" not in out


def test_fence_cannot_be_closed_by_content():
    text = "before\n```\ninjected markdown\n````\nafter"
    fenced = render.fence(text)
    opener = fenced.split("\n", 1)[0]
    assert set(opener) == {"`"} and len(opener) == 5
    assert fenced.endswith("\n" + opener)


def test_inline_and_code_spans():
    assert "|" not in render.inline("a|b").replace("\\|", "")
    assert render.code("x`y") == "`x'y`"


def test_pr_body_contents(report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    body = render.pr_body(
        c, _triage(c), _fixed(c), "claude-opus-5-5", "https://github.com", "o/r", "42"
    )
    for expected in [
        "## Finding",
        "CWE-78",
        "gosec",
        "## Exploitability (triage)",
        "## Changes",
        "## Verification",
        "go test ./...",
        "Draft",
        "https://github.com/o/r/actions/runs/42",
        f"secubot:cluster={c.id}",
        "Adversarial review",
    ]:
        assert expected in body, expected
    assert "@someone" not in body  # agent text is sanitised
    assert len(body) < 65536


def test_issue_and_titles(report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    assert render.issue_title(c).startswith(f"[secfix:{c.id}] ")
    assert render.pr_title(c).startswith("security: ")
    body = render.issue_body(c, "analysis and adversarial review disagree", _triage(c))
    assert "needs a human" in body and "## What to do" in body
    assert "**Not planned**" in body and "180 days" in body


def test_summary(report):
    md = render.summary_markdown(report)
    assert "Scanned 33 results" in md and "nothing new to triage" in md
    assert "[... truncated]" not in md


def test_summary_groups_and_outcomes(report, cfg):
    import copy

    from secubot.state import RepoState, select

    rep = copy.deepcopy(report)
    ci = [c for c in rep.clusters if c.severity.rank >= 2][:3]  # medium and above
    for c in ci:
        for f in c.findings:
            f.path = ".github/workflows/ci.yml"
    sel = select(rep, RepoState(), cfg)
    fixed = cluster_by(rep, path="goapp/main.go", line=19)
    if fixed in ci:
        fixed = next(c for c in rep.clusters if c not in ci and c.id in sel.selected)
    triage = {fixed.id: _triage(fixed)}
    fixes = {fixed.id: _fixed(fixed)}
    actions = [
        {"type": "pull_request", "cluster_id": fixed.id, "url": "https://github.com/o/r/pull/7"},
        {"type": "state", "cluster_id": "-", "detail": "1 new, 1 active"},
    ]
    md = render.summary_markdown(rep, sel, triage, fixes, actions, repository="o/r")
    assert md.startswith("# secubot · o/r")
    assert "**1 draft PR** · 1 triaged" in md
    assert "[draft PR](https://github.com/o/r/pull/7)" in md and "tests ✓" in md
    assert "## Not handled this run" in md
    row = next(line for line in md.splitlines() if line.startswith("| CI/agent config"))
    assert f"| {len(ci)} |" in row and "paths.ignore_protected" in row
    assert fixed.id in md  # in the reasoning details, for finding the branch or issue
    dry = render.summary_markdown(rep, sel, triage, fixes, actions[:1], dry_run=True)
    assert "**Dry run.**" in dry


def test_short_cuts_on_words():
    assert render.short("Using variable interpolation with github context data", 30) == (
        "Using variable interpolation…"
    )
    assert render.short("a | b", 10) == "a \\| b"


def test_rescan_only_verification_is_called_out(report):
    from secubot.fix import Attempt, FixResult, StepResult

    c = cluster_by(report, path="goapp/main.go", line=19)
    r = FixResult(
        cluster_id=c.id,
        status="fixed",
        attempts=[Attempt(number=1, steps=[StepResult(name="rescan", command="gosec", ok=True)])],
    )
    assert "verified by the re-scan only" in render.verification_section(r)
    assert "re-scan only" not in render.verification_section(_fixed(c))


def test_summary_lists_expired_suppressions(report):
    import datetime as dt

    from secubot.config import Suppression
    from secubot.state import Selection

    old = Suppression(rule="G404", reason="simulation jitter only", expires=dt.date(2026, 1, 1))
    md = render.summary_markdown(
        report, Selection(selected=[], decisions=[], expired_suppressions=[old])
    )
    assert "## Expired suppressions" in md and "G404" in md
