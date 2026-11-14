from __future__ import annotations

import asyncio
import json

from conftest import cluster_by
from fakes import FakeFactory, analysis, challenge

from secubot.agent import TurnResult
from secubot.config import SecfixConfig
from secubot.fix import StepResult, agent_commands, fix_cluster, resolution_problems
from secubot.models import ScanReport
from secubot.triage import Analysis, Challenge, TriageResult

CFG = {"commands": {"build": "go build ./...", "test": "go test ./..."}}


def _triage(cluster) -> TriageResult:
    return TriageResult(
        cluster_id=cluster.id,
        action="fix",
        final_verdict="true_positive",
        reason="ok",
        analysis=Analysis.model_validate(analysis()),
        challenge=Challenge.model_validate(challenge()),
    )


def _edit(path: str, old: str, new: str, summary: str = "use exec without shell"):
    """Simulate the agent's Edit tool: goes through the gate like the real hook would."""

    def step(spec, prompt):
        decision = spec.gate.check("Edit", {"file_path": str(spec.cwd / path)})
        if decision.allowed:
            f = spec.cwd / path
            f.write_text(f.read_text().replace(old, new))
        return TurnResult(
            structured={
                "summary": summary,
                "changes": [f"{path}: {summary}"],
                "risk_notes": "",
                "blocked_reason": "",
                "injection_suspected": False,
            },
            cost_usd=1.0,
        )

    return step


FIX_LINE = ('exec.Command("sh", "-c", name)', "exec.Command(name)")


def test_fix_verified_first_attempt(report, project, tmp_path):
    cluster = cluster_by(report, path="goapp/main.go", line=19)
    cfg = SecfixConfig.model_validate(CFG)
    calls = []

    def verifier(c, attempt):
        calls.append(attempt)
        return [StepResult(name="test", command="go test ./...", ok=True)], []

    factory = FakeFactory([[_edit("goapp/main.go", *FIX_LINE)]])
    out = tmp_path / "out"
    r = asyncio.run(fix_cluster(cluster, _triage(cluster), cfg, project, out, factory, verifier))
    assert r.status == "fixed" and calls == [1]
    patch = (out / "patch.diff").read_text()
    assert "+\tcmd := exec.Command(name)" in patch
    assert json.loads((out / "result.json").read_text())["status"] == "fixed"
    spec = factory.specs[0]
    assert spec.gate.policy.allow_edit and not spec.gate.policy.allow_write
    assert spec.gate.policy.bash_commands == ["go build ./...", "go test ./...", "secubot recheck"]
    assert spec.extra_env["SECUBOT_RECHECK_CLUSTER"] == cluster.id
    prompt = factory.prompts[0][0]
    assert "Fix only this finding" in prompt and "`go test ./...`" in prompt
    assert factory.closed == 1


def test_scrub_stubs_stay_out_of_verification(report, project, tmp_path):
    cluster = cluster_by(report, path="goapp/main.go", line=19)
    cfg = SecfixConfig.model_validate(CFG)
    before = sorted(p.name for p in project.iterdir())
    seen = {}
    edit = _edit("goapp/main.go", *FIX_LINE)

    def turn(spec, prompt):
        for name in ("package.json", "package-lock.json", ".env"):
            (spec.cwd / name).open("a").close()
        seen["package.json"] = (spec.cwd / "package.json").read_text()
        return edit(spec, prompt)

    def verifier(c, attempt):
        seen["verified"] = sorted(p.name for p in project.iterdir())
        return [StepResult(name="test", command="go test ./...", ok=True)], []

    factory = FakeFactory([[turn]])
    r = asyncio.run(
        fix_cluster(cluster, _triage(cluster), cfg, project, tmp_path / "o", factory, verifier)
    )
    assert r.status == "fixed"
    assert seen == {"package.json": "{}\n", "verified": before}
    assert sorted(p.name for p in project.iterdir()) == before


def test_fix_retries_with_feedback(report, project, tmp_path):
    cluster = cluster_by(report, path="goapp/main.go", line=19)
    cfg = SecfixConfig.model_validate(CFG)
    results = iter(
        [
            (
                [
                    StepResult(
                        name="test",
                        command="go test ./...",
                        ok=False,
                        exit_code=1,
                        output_tail="--- FAIL: TestRun (0.00s)",
                    )
                ],
                ["`go test ./...` failed"],
            ),
            ([StepResult(name="test", command="go test ./...", ok=True)], []),
        ]
    )
    factory = FakeFactory(
        [
            [
                _edit("goapp/main.go", *FIX_LINE),
                _edit("goapp/main.go", "return cmd.Run()", "return cmd.Run() "),
            ]
        ]
    )
    r = asyncio.run(
        fix_cluster(
            cluster,
            _triage(cluster),
            cfg,
            project,
            tmp_path / "o",
            factory,
            lambda c, n: next(results),
        )
    )
    assert r.status == "fixed" and len(r.attempts) == 2
    retry_prompt = factory.prompts[0][1]
    assert "attempt 1 of 3" in retry_prompt and "--- FAIL: TestRun" in retry_prompt
    assert r.cost_usd == 2.0


def test_protected_edit_fails_validation_then_gives_up(report, project, tmp_path):
    cluster = cluster_by(report, path="goapp/main.go", line=19)
    cfg = SecfixConfig.model_validate({**CFG, "fix": {"max_attempts": 2}})
    (project / ".github").mkdir()
    (project / ".github" / "ci.yml").write_text("on: push\n")
    from conftest import git

    git(project, "add", "-A")
    git(project, "commit", "-q", "-m", "ci")

    def sneaky(spec, prompt):
        # Pretend some tool wrote to CI config behind the gate's back.
        (spec.cwd / ".github" / "ci.yml").write_text("on: push\njobs: {}\n")
        return TurnResult(
            structured={
                "summary": "done",
                "changes": [],
                "risk_notes": "",
                "blocked_reason": "",
                "injection_suspected": False,
            }
        )

    factory = FakeFactory([[sneaky, sneaky]])
    out = tmp_path / "o"
    r = asyncio.run(
        fix_cluster(cluster, _triage(cluster), cfg, project, out, factory, lambda c, n: ([], []))
    )
    assert r.status == "failed" and "not verified after 2 attempts" in r.reason
    assert any("protected path" in p for p in r.attempts[0].problems)
    assert "protected path" in factory.prompts[0][1]
    assert not (out / "patch.diff").exists()


def test_blocked_and_injection(report, project, tmp_path):
    cluster = cluster_by(report, path="goapp/main.go", line=19)
    cfg = SecfixConfig.model_validate(CFG)
    blocked = {
        "summary": "",
        "changes": [],
        "risk_notes": "",
        "blocked_reason": "needs a credential rotation",
        "injection_suspected": False,
    }
    r = asyncio.run(
        fix_cluster(
            cluster,
            _triage(cluster),
            cfg,
            project,
            tmp_path / "a",
            FakeFactory([[blocked]]),
            lambda c, n: ([], []),
        )
    )
    assert r.status == "blocked" and "rotation" in r.reason
    injected = {**blocked, "blocked_reason": "", "injection_suspected": True}
    r = asyncio.run(
        fix_cluster(
            cluster,
            _triage(cluster),
            cfg,
            project,
            tmp_path / "b",
            FakeFactory([[injected]]),
            lambda c, n: ([], []),
        )
    )
    assert r.status == "blocked" and "injection" in r.reason


def test_setup_failure_is_an_error(report, project, tmp_path):
    cluster = cluster_by(report, path="goapp/main.go", line=19)
    cfg = SecfixConfig.model_validate({"commands": {"setup": "exit 3"}})
    factory = FakeFactory([])
    r = asyncio.run(
        fix_cluster(
            cluster, _triage(cluster), cfg, project, tmp_path / "o", factory, lambda c, n: ([], [])
        )
    )
    assert r.status == "error" and not factory.specs


def test_setup_runs_with_scrubbed_env(report, project, tmp_path, monkeypatch):
    cluster = cluster_by(report, path="goapp/main.go", line=19)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-value")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_test")
    cfg = SecfixConfig.model_validate(
        {"commands": {"setup": 'test -z "$ANTHROPIC_API_KEY" && test -z "$GITHUB_TOKEN"'}}
    )
    blocked = {
        "summary": "",
        "changes": [],
        "risk_notes": "",
        "blocked_reason": "stop",
        "injection_suspected": False,
    }
    r = asyncio.run(
        fix_cluster(
            cluster,
            _triage(cluster),
            cfg,
            project,
            tmp_path / "o",
            FakeFactory([[blocked]]),
            lambda c, n: ([], []),
        )
    )
    assert r.status == "blocked"  # setup passed, so the secrets were not visible


def test_agent_commands_for_dependency(report, project):
    xtext = cluster_by(report, package="golang.org/x/text")
    cmds = agent_commands(xtext, SecfixConfig.model_validate(CFG), project)
    assert "go get:*" in cmds and "go mod tidy" in cmds and "secubot recheck" in cmds


def test_resolution_problems(report):
    cluster = cluster_by(report, path="goapp/main.go", line=19)
    remaining = [f for f in report.findings if f.fingerprint not in set(cluster.fingerprints)]
    after = ScanReport(
        raw_results=0,
        findings=remaining,
        clusters=[c for c in report.clusters if c.id != cluster.id],
    )
    assert resolution_problems(cluster, report, after) == []
    assert resolution_problems(cluster, report, report)
    xtext = cluster_by(report, package="golang.org/x/text")
    assert any("still reported" in p for p in resolution_problems(xtext, report, report))
