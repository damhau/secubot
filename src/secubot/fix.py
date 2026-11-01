"""Fix: one cluster per job, one Claude Code session, bounded verification loop.

    agent edits -> patch checks -> setup/build/test -> re-run the scanners that raised it
       ^                                                         |
       +---------------- failure output fed back (max N) --------+

The pipeline, not the agent, decides whether the fix is verified: the agent may run the
build/tests itself to iterate, but the verdict comes from this module re-running every
step with a scrubbed environment.
"""

from __future__ import annotations

import subprocess
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from secubot import prompts
from secubot.agent import AgentFactory, SessionSpec
from secubot.config import SecfixConfig
from secubot.gate import Gate, GatePolicy
from secubot.models import Cluster, Kind, ScanReport
from secubot.normalise import normalise
from secubot.patch import diffstat, validate_patch
from secubot.scanners import ALL_TOOLS, run_scanners, scrubbed_env
from secubot.triage import TriageResult

FIX_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "changes": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
        "risk_notes": {"type": "string"},
        "blocked_reason": {"type": "string"},
        "injection_suspected": {"type": "boolean"},
    },
    "required": ["summary", "changes", "risk_notes", "blocked_reason", "injection_suspected"],
    "additionalProperties": False,
}

RECHECK_COMMAND = "secubot recheck"


class FixOutput(BaseModel):
    summary: str = ""
    changes: list[str] = Field(default_factory=list)
    risk_notes: str = ""
    blocked_reason: str = ""
    injection_suspected: bool = False


class StepResult(BaseModel):
    name: str
    command: str
    ok: bool
    exit_code: int | None = None
    duration_s: float = 0.0
    output_tail: str = ""


class Attempt(BaseModel):
    number: int
    agent_summary: str = ""
    problems: list[str] = Field(default_factory=list)
    steps: list[StepResult] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


class FixResult(BaseModel):
    cluster_id: str
    status: Literal["fixed", "failed", "blocked", "error"]
    reason: str = ""
    attempts: list[Attempt] = Field(default_factory=list)
    output: FixOutput | None = None
    diffstat: str = ""
    cost_usd: float = 0.0
    tool_calls: list[dict] = Field(default_factory=list)
    denied_tool_calls: int = 0


Verifier = Callable[[Cluster, int], tuple[list[StepResult], list[str]]]


# -- shell steps ------------------------------------------------------------------------------


def run_step(name: str, command: str, cwd: Path, timeout_s: int) -> StepResult:
    start = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S602 - commands come from the repo's own .secfix.yml
            command,
            shell=True,
            cwd=cwd,
            env=scrubbed_env(),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        return StepResult(
            name=name,
            command=command,
            ok=proc.returncode == 0,
            exit_code=proc.returncode,
            duration_s=time.monotonic() - start,
            output_tail=out[-4000:],
        )
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else ""
        return StepResult(
            name=name,
            command=command,
            ok=False,
            duration_s=timeout_s,
            output_tail=f"timed out after {timeout_s}s\n{out[-3000:]}",
        )


# -- resolution check -------------------------------------------------------------------------


def _source_keys(report_or_findings) -> Counter:
    findings = (
        report_or_findings.findings
        if isinstance(report_or_findings, ScanReport)
        else (report_or_findings)
    )
    keys: Counter = Counter()
    for f in findings:
        for s in f.sources:
            keys[(s.tool, s.rule_id, f.path)] += 1
    return keys


def resolution_problems(cluster: Cluster, baseline: ScanReport, after: ScanReport) -> list[str]:
    """Is the cluster gone from the re-scan? Robust to the agent rewriting the flagged line."""
    problems = []
    if any(c.id == cluster.id for c in after.clusters):
        problems.append("the re-scan still reports this finding at the same location")
    remaining_fps = set(cluster.fingerprints) & {f.fingerprint for f in after.findings}
    if remaining_fps:
        problems.append(f"{len(remaining_fps)} of the cluster's findings are still reported")
    if cluster.kind == Kind.DEPENDENCY:
        wanted = set(cluster.vuln_ids)
        still = sorted({v for f in after.findings for v in f.vuln_ids if v in wanted})
        if still and not cluster.key.endswith("|image"):
            problems.append(f"vulnerabilities still reported: {', '.join(still[:10])}")
        elif still and len(still) >= len(wanted):
            problems.append("the image re-scan reports as many of these vulnerabilities as before")
    else:
        before, now = _source_keys(baseline), _source_keys(after)
        for key in {(s.tool, s.rule_id, f.path) for f in cluster.findings for s in f.sources}:
            if now[key] >= before[key] and now[key] > 0:
                tool, rule, path = key
                problems.append(f"{tool} still reports {rule} in {path} as often as before")
    return sorted(set(problems))


def make_verifier(
    cfg: SecfixConfig, repo_root: Path, baseline: ScanReport, workdir: Path
) -> Verifier:
    timeout_s = cfg.commands.timeout_minutes * 60

    def verify(cluster: Cluster, attempt: int) -> tuple[list[StepResult], list[str]]:
        steps: list[StepResult] = []
        for name, command in (("build", cfg.commands.build), ("test", cfg.commands.test)):
            if not command:
                continue
            step = run_step(name, command, repo_root, timeout_s)
            steps.append(step)
            if not step.ok:
                return steps, [f"`{command}` failed (exit {step.exit_code})"]
        tools = [t for t in cluster.tools if t in ALL_TOOLS]
        out = workdir / f"verify-{attempt}"
        start = time.monotonic()
        statuses = run_scanners(tools, repo_root, out, cfg)
        failed = [s for s in statuses if not s.ok]
        if failed:
            detail = "; ".join(f"{s.tool}: {s.detail[-500:]}" for s in failed)
            steps.append(
                StepResult(
                    name="rescan",
                    command=" ".join(tools),
                    ok=False,
                    duration_s=time.monotonic() - start,
                    output_tail=detail,
                )
            )
            return steps, [f"re-scan failed: {', '.join(s.tool for s in failed)}"]
        after = normalise(sorted(out.glob("*.sarif")), repo_root, cfg)
        problems = resolution_problems(cluster, baseline, after)
        steps.append(
            StepResult(
                name="rescan",
                command=", ".join(tools),
                ok=not problems,
                duration_s=time.monotonic() - start,
                output_tail="\n".join(problems) or "finding no longer reported",
            )
        )
        return steps, problems

    return verify


# -- git --------------------------------------------------------------------------------------


def _git(repo_root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args], capture_output=True, text=True, check=True
    ).stdout


def working_tree_diff(repo_root: Path, new_files: list[str]) -> str:
    """Tracked changes + files the agent created (build artefacts are not picked up)."""
    root = repo_root.resolve()
    for raw in new_files:
        p = Path(raw)
        p = p if p.is_absolute() else root / p
        try:
            rel = p.resolve().relative_to(root).as_posix()
        except ValueError:
            continue
        if p.is_file():
            _git(root, "add", "--intent-to-add", "--", rel)
    return _git(root, "diff", "--binary", "HEAD", "--")


# -- the loop ---------------------------------------------------------------------------------


def agent_commands(cluster: Cluster, cfg: SecfixConfig, repo_root: Path) -> list[str]:
    cmds = [c for c in (cfg.commands.build, cfg.commands.test) if c]
    cmds.append(RECHECK_COMMAND)
    if cluster.kind == Kind.DEPENDENCY:
        mdir = repo_root / Path(cluster.path).parent
        if (mdir / "go.mod").is_file():
            cmds += ["go mod tidy", "go get:*"]
        if (mdir / "uv.lock").is_file():
            cmds += ["uv lock:*"]
    cmds += cfg.fix.extra_commands
    return list(dict.fromkeys(cmds))


def _fix_prompt(cluster: Cluster, triage: TriageResult, cfg: SecfixConfig, cmds: list[str]) -> str:
    analysis = triage.analysis
    triage_text = "(no triage details)"
    if analysis is not None:
        triage_text = (
            f"verdict: {triage.final_verdict}; reachable: {analysis.reachable}; "
            f"exploitable: {analysis.exploitable}; severity: {analysis.severity.value}\n\n"
            f"reasoning:\n{analysis.reasoning}\n\nsuggested fix strategy:\n"
            f"{analysis.fix_strategy}"
        )
    new_files_rule = (
        "- You may create a new file only for a focused regression test of this finding.\n"
        if cfg.fix.allow_new_files
        else "- Do not create new files.\n"
    )
    commands = "\n".join(f"- `{c}`" for c in cmds)
    commands += (
        f"\n\n`{RECHECK_COMMAND}` re-runs the scanner(s) that reported this finding and tells "
        "you whether it is still reported."
    )
    return prompts.render(
        prompts.load("fix"),
        finding=prompts.finding_block(cluster),
        triage=prompts.neutralise(triage_text),
        commands=commands,
        max_files=str(cfg.fix.max_changed_files),
        max_lines=str(cfg.fix.max_changed_lines),
        new_files_rule=new_files_rule,
    )


def _retry_prompt(attempt: Attempt, cfg: SecfixConfig) -> str:
    failing = next((s for s in reversed(attempt.steps) if not s.ok), None)
    output = failing.output_tail if failing else "\n".join(attempt.problems)
    return prompts.render(
        prompts.load("fix_retry"),
        attempt=str(attempt.number),
        max_attempts=str(cfg.fix.max_attempts),
        problems="\n".join(f"- {p}" for p in attempt.problems),
        output=prompts.neutralise(output[-4000:]),
    )


async def fix_cluster(
    cluster: Cluster,
    triage: TriageResult,
    cfg: SecfixConfig,
    repo_root: Path,
    out_dir: Path,
    factory: AgentFactory,
    verifier: Verifier,
    scan_dir: Path | None = None,
) -> FixResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    result = FixResult(cluster_id=cluster.id, status="failed")

    if cfg.commands.setup:
        step = run_step("setup", cfg.commands.setup, repo_root, cfg.commands.timeout_minutes * 60)
        if not step.ok:
            result.status, result.reason = "error", f"setup command failed: {step.output_tail}"
            result.attempts.append(Attempt(number=0, problems=["setup failed"], steps=[step]))
            return _finish(result, out_dir, "")

    cmds = agent_commands(cluster, cfg, repo_root)
    gate = Gate(
        GatePolicy(
            root=repo_root,
            allow_edit=True,
            allow_write=cfg.fix.allow_new_files,
            bash_commands=cmds,
            protected=cfg.protected_spec(),
        )
    )
    extra_env = {"SECUBOT_RECHECK_CLUSTER": cluster.id}
    if scan_dir is not None:
        extra_env["SECUBOT_SCAN_DIR"] = str(scan_dir.resolve())
        extra_env["SECUBOT_REPO_ROOT"] = str(repo_root.resolve())
    spec = SessionSpec(
        cwd=repo_root,
        model=cfg.models.fix,
        system_append=prompts.load("system"),
        gate=gate,
        output_schema=FIX_SCHEMA,
        max_turns=cfg.models.fix_max_turns,
        max_budget_usd=cfg.models.fix_budget_usd,
        effort=cfg.models.effort,
        extra_env=extra_env,
    )
    session = factory(spec)
    prompt = _fix_prompt(cluster, triage, cfg, cmds)
    diff = ""
    try:
        for number in range(1, cfg.fix.max_attempts + 1):
            turn = await session.turn(prompt)
            result.cost_usd += turn.cost_usd
            if turn.is_error:
                result.status, result.reason = "error", f"agent session failed: {turn.error}"
                break
            output = FixOutput.model_validate(turn.structured or {"summary": turn.text[:2000]})
            result.output = output
            attempt = Attempt(number=number, agent_summary=output.summary[:2000])
            result.attempts.append(attempt)
            if output.injection_suspected:
                result.status = "blocked"
                result.reason = "agent reported a possible prompt injection; needs a human"
                break
            if output.blocked_reason.strip():
                result.status, result.reason = "blocked", output.blocked_reason.strip()[:2000]
                break
            diff = working_tree_diff(repo_root, gate.written_files())
            attempt.problems = validate_patch(diff, cluster, cfg)
            if not attempt.problems:
                attempt.steps, attempt.problems = verifier(cluster, number)
            if attempt.ok:
                result.status, result.reason = "fixed", "verified"
                break
            prompt = _retry_prompt(attempt, cfg)
        else:
            result.reason = f"not verified after {cfg.fix.max_attempts} attempts"
    finally:
        await session.close()

    result.tool_calls = gate.log[-200:]
    result.denied_tool_calls = sum(1 for e in gate.log if not e["allowed"])
    return _finish(result, out_dir, diff if result.status == "fixed" else "")


def _finish(result: FixResult, out_dir: Path, diff: str) -> FixResult:
    if diff:
        (out_dir / "patch.diff").write_text(diff, encoding="utf-8")
        result.diffstat = diffstat(diff)
    (out_dir / "result.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return result


def recheck(cluster: Cluster, baseline: ScanReport, cfg: SecfixConfig, repo_root: Path) -> str:
    """Used by the agent through `secubot recheck` while iterating."""
    tools = [t for t in cluster.tools if t in ALL_TOOLS]
    with tempfile.TemporaryDirectory(prefix="secubot-recheck-") as tmp:
        statuses = run_scanners(tools, repo_root, Path(tmp), cfg)
        failed = [s for s in statuses if not s.ok]
        if failed:
            return "re-scan failed: " + "; ".join(f"{s.tool}: {s.detail[-300:]}" for s in failed)
        after = normalise(sorted(Path(tmp).glob("*.sarif")), repo_root, cfg)
    problems = resolution_problems(cluster, baseline, after)
    if not problems:
        return f"OK: {', '.join(tools)} no longer report this finding."
    return "STILL REPORTED:\n" + "\n".join(f"- {p}" for p in problems)
