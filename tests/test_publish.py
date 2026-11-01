from __future__ import annotations

import datetime as dt
import json
import subprocess

import pytest
from conftest import cluster_by, git
from fakes import analysis, challenge

from secubot.config import SecfixConfig, Suppression
from secubot.fix import Attempt, FixOutput, FixResult, StepResult
from secubot.publish import Inputs, Publisher, Runner, load_inputs
from secubot.state import STATE_BRANCH, parse_state_suppressions
from secubot.triage import Analysis, Challenge, TriageResult

TODAY = dt.date(2026, 11, 1)
PATCH = """diff --git a/goapp/main.go b/goapp/main.go
--- a/goapp/main.go
+++ b/goapp/main.go
@@ -16,7 +16,7 @@ func token() int {
 }
 
 func run(name string) error {
-\tcmd := exec.Command("sh", "-c", name)
+\tcmd := exec.Command(name)
 \treturn cmd.Run()
 }
 
"""


class FakeGhRunner(Runner):
    """Real git against a local bare remote; `gh` is recorded and answered locally."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.gh_calls: list[list[str]] = []
        self.views: dict[tuple[str, int], dict] = {}

    def run(self, *cmd, input=None, check=True, mutating=False):
        if cmd[0] == "gh":
            self.gh_calls.append(list(cmd))
            self.calls.append(list(cmd))
            out = ""
            if cmd[1:3] == ("pr", "create"):
                out = "https://github.com/o/r/pull/7\n"
            elif cmd[1:3] == ("issue", "create"):
                out = "https://github.com/o/r/issues/8\n"
            elif cmd[1:3] == ("issue", "list"):
                out = "[]"
            elif cmd[2:3] == ("view",):
                view = self.views.get((cmd[1], int(cmd[3])))
                if view is None:
                    return subprocess.CompletedProcess(list(cmd), 1, "", "not found")
                out = json.dumps(view)
            return subprocess.CompletedProcess(list(cmd), 0, out, "")
        return super().run(*cmd, input=input, check=check, mutating=mutating)


@pytest.fixture
def remote(project, tmp_path):
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    git(project, "remote", "add", "origin", str(bare))
    git(project, "push", "-q", "origin", "main")
    return bare


def _fixed(cluster) -> FixResult:
    return FixResult(
        cluster_id=cluster.id,
        status="fixed",
        reason="verified",
        attempts=[
            Attempt(
                number=1,
                steps=[
                    StepResult(
                        name="test", command="go test ./...", ok=True, output_tail="ok  example"
                    )
                ],
            )
        ],
        output=FixOutput(
            summary="Run the binary without a shell @someone", changes=["goapp/main.go: no sh -c"]
        ),
        diffstat="goapp/main.go | +1 -1",
        cost_usd=1.5,
    )


def _triage(cluster, action="fix", **kw) -> TriageResult:
    return TriageResult(
        cluster_id=cluster.id,
        action=action,
        final_verdict="true_positive",
        reason="analysis upheld",
        analysis=Analysis.model_validate(analysis()),
        challenge=Challenge.model_validate(challenge()),
        cost_usd=1.0,
        **kw,
    )


def _publisher(project, report, triage, fixes, patches, dry_run=False):
    runner = FakeGhRunner(cwd=project, dry_run=dry_run)
    pub = Publisher(
        runner=runner,
        cfg=SecfixConfig(),
        base_branch="main",
        repo="o/r",
        server="https://github.com",
        run_id="42",
        inputs=Inputs(report, triage, fixes, patches),
    )
    return pub, runner


def test_pr_flow_pushes_branch_and_opens_draft(project, remote, report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    pub, runner = _publisher(project, report, {c.id: _triage(c)}, {c.id: _fixed(c)}, {c.id: PATCH})
    actions = pub.run(TODAY)
    assert [a["type"] for a in actions] == ["pull_request"]
    heads = subprocess.run(
        ["git", "-C", str(remote), "branch", "--list"], capture_output=True, text=True, check=True
    ).stdout
    assert f"secfix/{c.id}" in heads
    log = subprocess.run(
        ["git", "-C", str(remote), "log", "-1", "--format=%an|%B", f"secfix/{c.id}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert log.startswith("github-actions[bot]|security: ")
    assert "Co-authored-by" not in log
    create = next(c for c in runner.gh_calls if c[1:3] == ["pr", "create"])
    assert "--draft" in create and create[create.index("--label") + 1] == "security"
    assert "--base" in create and create[create.index("--base") + 1] == "main"


def test_existing_branch_is_idempotent(project, remote, report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    git(project, "push", "-q", "origin", f"main:refs/heads/secfix/{c.id}")
    pub, runner = _publisher(project, report, {c.id: _triage(c)}, {c.id: _fixed(c)}, {c.id: PATCH})
    actions = pub.run(TODAY)
    assert actions[0]["type"] == "skipped" and "already exists" in actions[0]["detail"]
    assert not any(c[1:3] == ["pr", "create"] for c in runner.gh_calls)


def test_bad_patch_is_rejected_at_publish(project, remote, report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    evil = PATCH.replace("goapp/main.go", ".github/workflows/ci.yml")
    pub, runner = _publisher(project, report, {c.id: _triage(c)}, {c.id: _fixed(c)}, {c.id: evil})
    actions = pub.run(TODAY)
    kinds = [a["type"] for a in actions]
    assert "rejected" in kinds and "issue" in kinds and "pull_request" not in kinds
    heads = subprocess.run(
        ["git", "-C", str(remote), "branch", "--list"], capture_output=True, text=True, check=True
    ).stdout
    assert "secfix/" not in heads


def test_suppressions_go_to_the_state_branch(project, remote, report):
    c = cluster_by(report, path="goapp/main.go", line=24)
    s = Suppression(
        id=c.id,
        reason="secubot triage: false positive, test code",
        expires=TODAY + dt.timedelta(days=30),
        created=TODAY,
        source="triage",
    )
    t = _triage(c, action="suppress", suppression=s)
    pub, _ = _publisher(project, report, {c.id: t}, {}, {})
    actions = pub.run(TODAY)
    assert {a["type"] for a in actions} == {"suppressed", "state"}
    content = subprocess.run(
        ["git", "-C", str(remote), "show", f"{STATE_BRANCH}:suppressions.yml"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert parse_state_suppressions(content) == [s]
    # Second run with another suppression: appended on top of the existing commit; the
    # expired one is dropped.
    old = Suppression(
        id="0" * 12,
        reason="this one has expired already",
        expires=TODAY - dt.timedelta(days=1),
        source="triage",
    )
    pub2, _ = _publisher(
        project, report, {c.id: _triage(c, action="suppress", suppression=old)}, {}, {}
    )
    pub2.run(TODAY)
    count = subprocess.run(
        ["git", "-C", str(remote), "rev-list", "--count", STATE_BRANCH],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert count == "1"  # nothing changed (expired entry dropped), so no new commit
    # main is untouched by state updates
    files = subprocess.run(
        ["git", "-C", str(remote), "ls-tree", "--name-only", STATE_BRANCH],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert files == ["README.md", "suppressions.yml"]


def test_issues_for_uncertain_and_failed(project, remote, report):
    a = cluster_by(report, path="goapp/main.go", line=24)
    b = cluster_by(report, path="goapp/main.go", line=19)
    failed = FixResult(cluster_id=b.id, status="failed", reason="not verified after 3 attempts")
    pub, runner = _publisher(
        project, report, {a.id: _triage(a, action="issue"), b.id: _triage(b)}, {b.id: failed}, {}
    )
    actions = pub.run(TODAY)
    assert [x["type"] for x in actions] == ["issue", "issue"]
    titles = [c[c.index("--title") + 1] for c in runner.gh_calls if c[1:3] == ["issue", "create"]]
    assert all(t.startswith("[secfix:") for t in titles)


def test_dry_run_changes_nothing(project, remote, report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    pub, runner = _publisher(
        project, report, {c.id: _triage(c)}, {c.id: _fixed(c)}, {c.id: PATCH}, dry_run=True
    )
    pub.run(TODAY)
    heads = subprocess.run(
        ["git", "-C", str(remote), "branch", "--list"], capture_output=True, text=True, check=True
    ).stdout
    assert "secfix/" not in heads


def test_load_inputs(tmp_path, report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    (tmp_path / "scan").mkdir()
    (tmp_path / "scan" / "report.json").write_text(report.model_dump_json())
    (tmp_path / "triage").mkdir()
    (tmp_path / "triage" / "triage.json").write_text(
        json.dumps([_triage(c).model_dump(mode="json")])
    )
    d = tmp_path / "fix" / f"secubot-fix-{c.id}"
    d.mkdir(parents=True)
    (d / "result.json").write_text(_fixed(c).model_dump_json())
    (d / "patch.diff").write_text(PATCH)
    inputs = load_inputs(tmp_path / "scan", tmp_path / "triage", tmp_path / "fix")
    assert inputs.patches[c.id] == PATCH and inputs.fixes[c.id].status == "fixed"


def test_load_inputs_ignores_untriaged_fix_artifacts(tmp_path, report):
    """A fix job runs repository code; its artifact is only trusted for its own cluster."""
    c = cluster_by(report, path="goapp/main.go", line=19)
    other = cluster_by(report, path="goapp/main.go", line=24)
    (tmp_path / "scan").mkdir()
    (tmp_path / "scan" / "report.json").write_text(report.model_dump_json())
    (tmp_path / "triage").mkdir()
    (tmp_path / "triage" / "triage.json").write_text(
        json.dumps([_triage(c).model_dump(mode="json")])
    )
    for name, cid in [
        (f"secubot-fix-{other.id}", other.id),  # not triaged as fix
        (f"secubot-fix-{c.id}x", c.id),  # directory does not match the cluster
        ("secubot-fix-evil", "../../main"),
    ]:
        d = tmp_path / "fix" / name
        d.mkdir(parents=True)
        fixed = _fixed(c).model_copy(update={"cluster_id": cid})
        (d / "result.json").write_text(fixed.model_dump_json())
        (d / "patch.diff").write_text(PATCH)
    inputs = load_inputs(tmp_path / "scan", tmp_path / "triage", tmp_path / "fix")
    assert inputs.fixes == {} and inputs.patches == {}
    assert len(inputs.ignored) == 3
    assert c.id in inputs.rejected


def test_load_inputs_refuses_a_flat_fix_artifact(tmp_path, report):
    """download-artifact unpacks a lone match straight into `path` (second rami run)."""
    c = cluster_by(report, path="goapp/main.go", line=19)
    (tmp_path / "scan").mkdir()
    (tmp_path / "scan" / "report.json").write_text(report.model_dump_json())
    (tmp_path / "triage").mkdir()
    (tmp_path / "triage" / "triage.json").write_text(
        json.dumps([_triage(c).model_dump(mode="json")])
    )
    (tmp_path / "fix").mkdir()
    (tmp_path / "fix" / "result.json").write_text(_fixed(c).model_dump_json())
    inputs = load_inputs(tmp_path / "scan", tmp_path / "triage", tmp_path / "fix")
    assert inputs.fixes == {}
    assert "own artifact directory" in inputs.rejected[c.id]
    # with the artifact directory, the same result is accepted
    artifact = tmp_path / "fix" / f"secubot-fix-{c.id}"
    artifact.mkdir()
    (tmp_path / "fix" / "result.json").rename(artifact / "result.json")
    inputs = load_inputs(tmp_path / "scan", tmp_path / "triage", tmp_path / "fix")
    assert c.id in inputs.fixes and inputs.rejected == {}


def _marker(cid, instance="", kind="code"):
    return f"body\n<!-- secubot:cluster={cid} instance={instance} kind={kind} fingerprints=x -->"


@pytest.mark.parametrize("dry_run", [False, True])
def test_auto_close_checks_each_item_again(project, remote, report, dry_run):
    from secubot.state import Resolved

    pr, legacy, secret, other, gone = "b" * 12, "c" * 12, "a" * 12, "d" * 12, "e" * 12
    git(project, "push", "-q", "origin", f"main:refs/heads/secfix/{pr}")
    resolved = [
        Resolved(cluster_id=pr, item="pull_request", number=41, title="security: x"),
        Resolved(cluster_id=legacy, item="issue", number=42, title=f"[secfix:{legacy}] anyio"),
        Resolved(cluster_id=secret, item="issue", number=43),
        Resolved(cluster_id=other, item="issue", number=44),
        Resolved(cluster_id=gone, item="issue", number=45),
    ]
    pub, runner = _publisher(project, report, {}, {}, {}, dry_run=dry_run)
    pub.inputs.resolved = resolved
    runner.views = {
        ("pr", 41): {"state": "OPEN", "body": _marker(pr)},
        ("issue", 42): {
            "state": "OPEN",
            "body": f"<!-- secubot:cluster={legacy} fingerprints=x -->",
        },
        ("issue", 43): {"state": "OPEN", "body": _marker(secret, kind="secret")},
        ("issue", 44): {"state": "OPEN", "body": _marker(other, instance="-api")},
        ("issue", 45): {"state": "CLOSED", "body": _marker(gone)},
    }
    actions = {a["cluster_id"]: a for a in pub.run(TODAY)}
    assert actions[pr]["type"] == "closed" and actions[legacy]["type"] == "closed"
    assert actions[secret]["type"] == "kept_open"
    assert actions[other]["type"] == "skipped" and "-api" in actions[other]["detail"]
    assert actions[gone]["type"] == "skipped" and "no longer open" in actions[gone]["detail"]
    closes = [c for c in runner.gh_calls if c[2:3] == ["close"]]
    assert [(c[1], c[3]) for c in closes] == [("pr", "41"), ("issue", "42")]
    issue_close = closes[1]
    assert issue_close[issue_close.index("--reason") + 1] == "completed"
    assert "no longer finds this" in issue_close[issue_close.index("--comment") + 1]
    heads = subprocess.run(
        ["git", "-C", str(remote), "branch", "--list"], capture_output=True, text=True, check=True
    ).stdout
    assert (f"secfix/{pr}" in heads) == dry_run  # the PR's branch is deleted, unless dry run


def test_load_inputs_drops_resolved_items_that_are_still_reported(tmp_path, report):
    from secubot.state import Resolved, Selection

    present = report.clusters[0].id
    (tmp_path / "report.json").write_text(report.model_dump_json())
    sel = Selection(
        selected=[],
        decisions=[],
        resolved=[
            Resolved(cluster_id=present, item="issue", number=1),
            Resolved(cluster_id="not-an-id", item="issue", number=2),
            Resolved(cluster_id="f" * 12, item="issue", number=3),
        ],
    )
    (tmp_path / "selection.json").write_text(sel.model_dump_json())
    inputs = load_inputs(tmp_path, None, None)
    assert [r.number for r in inputs.resolved] == [3]
