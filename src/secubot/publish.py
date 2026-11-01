"""Publish: the only step that holds write permissions.

It never runs repository code and never talks to the model. It reads the artifacts of the
previous jobs, re-validates every patch (the fix job is untrusted from here), and then
creates branches, draft PRs and issues with `git`/`gh`, and updates the state branch.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from secubot import render
from secubot.config import SecfixConfig, Suppression
from secubot.fix import FixResult
from secubot.models import ScanReport
from secubot.patch import validate_patch
from secubot.state import (
    ISSUE_TITLE_RE,
    STATE_BRANCH,
    STATE_FILE,
    dump_state_suppressions,
    parse_state_suppressions,
)
from secubot.triage import TriageResult

LABEL_COLOR = "B60205"
STATE_README = """# secubot state

This orphan branch is written by the secubot publish job. `suppressions.yml` lists
findings that triage and the adversarial review agreed are false positives. Every entry
has a reason and an expiry date; expired entries are dropped and re-triaged.

Delete an entry (or this branch) to force re-triage. Permanent suppressions belong in
`.secfix.yml` on the default branch, where they are code-reviewed.
"""


class PublishError(RuntimeError):
    pass


@dataclass
class Runner:
    """git/gh runner. In dry-run mode, mutating commands are recorded and skipped."""

    cwd: Path
    dry_run: bool = False
    calls: list[list[str]] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    def run(
        self, *cmd: str, input: str | None = None, check: bool = True, mutating: bool = False
    ) -> subprocess.CompletedProcess:
        self.calls.append(list(cmd))
        if self.dry_run and mutating:
            return subprocess.CompletedProcess(list(cmd), 0, "", "")
        proc = subprocess.run(
            list(cmd),
            cwd=self.cwd,
            input=input,
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, **self.env},
        )
        if check and proc.returncode != 0:
            raise PublishError(f"{' '.join(cmd[:3])} failed: {proc.stderr.strip()[-800:]}")
        return proc

    def git(self, *args: str, **kw) -> subprocess.CompletedProcess:
        return self.run("git", "-c", "core.hooksPath=/dev/null", *args, **kw)

    def gh(self, *args: str, **kw) -> subprocess.CompletedProcess:
        return self.run("gh", *args, **kw)


@dataclass
class Inputs:
    report: ScanReport
    triage: dict[str, TriageResult]
    fixes: dict[str, FixResult]
    patches: dict[str, str]
    ignored: list[str] = field(default_factory=list)


CLUSTER_ID_RE = re.compile(r"[0-9a-f]{12}")


def load_inputs(scan_dir: Path, triage_dir: Path | None, fix_dir: Path | None) -> Inputs:
    """Load job artifacts. Fix artifacts come from jobs that ran repository code, so they are
    only accepted for clusters this run scanned and triaged as `fix`."""
    report = ScanReport.model_validate_json((scan_dir / "report.json").read_text())
    known = {c.id for c in report.clusters}
    ignored: list[str] = []
    triage: dict[str, TriageResult] = {}
    if triage_dir and (triage_dir / "triage.json").is_file():
        for item in json.loads((triage_dir / "triage.json").read_text()):
            t = TriageResult.model_validate(item)
            if t.cluster_id in known:
                triage[t.cluster_id] = t
            else:
                ignored.append(f"triage result for unknown cluster {t.cluster_id[:40]!r}")
    fixes: dict[str, FixResult] = {}
    patches: dict[str, str] = {}
    if fix_dir and fix_dir.is_dir():
        for result_file in sorted(fix_dir.glob("**/result.json")):
            r = FixResult.model_validate_json(result_file.read_text())
            cid = r.cluster_id
            t = triage.get(cid)
            if not CLUSTER_ID_RE.fullmatch(cid) or t is None or t.action != "fix":
                ignored.append(f"fix result for a cluster not triaged as fix: {cid[:40]!r}")
                continue
            if not result_file.parent.name.endswith(f"-fix-{cid}") or cid in fixes:
                ignored.append(f"fix result {cid} in an unexpected or duplicate artifact")
                continue
            fixes[cid] = r
            patch = result_file.parent / "patch.diff"
            if patch.is_file():
                patches[cid] = patch.read_text()
    return Inputs(report, triage, fixes, patches, ignored)


@dataclass
class Publisher:
    runner: Runner
    cfg: SecfixConfig
    inputs: Inputs
    base_branch: str
    server: str = ""
    repo: str = ""
    run_id: str = ""
    git_name: str = "github-actions[bot]"
    git_email: str = "41898282+github-actions[bot]@users.noreply.github.com"
    actions: list[dict] = field(default_factory=list)

    # -- helpers --------------------------------------------------------------------------

    def _record(self, kind: str, cluster_id: str, **extra) -> None:
        self.actions.append({"type": kind, "cluster_id": cluster_id, **extra})

    def _ident_env(self) -> dict[str, str]:
        return {
            "GIT_AUTHOR_NAME": self.git_name,
            "GIT_AUTHOR_EMAIL": self.git_email,
            "GIT_COMMITTER_NAME": self.git_name,
            "GIT_COMMITTER_EMAIL": self.git_email,
        }

    def _remote_branch_exists(self, branch: str) -> bool:
        proc = self.runner.git(
            "ls-remote", "--exit-code", "--heads", "origin", f"refs/heads/{branch}", check=False
        )
        return proc.returncode == 0

    def _open_issue_exists(self, cluster_id: str) -> str | None:
        proc = self.runner.gh(
            "issue",
            "list",
            "--state",
            "open",
            "--search",
            f"secfix:{cluster_id} in:title",
            "--json",
            "number,title,url",
            "--limit",
            "20",
            check=False,
        )
        try:
            items = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            return None
        for item in items:
            m = ISSUE_TITLE_RE.search(item.get("title", ""))
            if m and m.group(1) == cluster_id:
                return item.get("url", "")
        return None

    def ensure_labels(self) -> None:
        for label in self.cfg.labels:
            self.runner.gh(
                "label",
                "create",
                label,
                "--color",
                LABEL_COLOR,
                "--description",
                "Opened by secubot",
                check=False,
                mutating=True,
            )

    # -- PRs ------------------------------------------------------------------------------

    def open_pr(self, cluster_id: str) -> None:
        report, cfg = self.inputs.report, self.cfg
        cluster = report.cluster(cluster_id)
        fix = self.inputs.fixes[cluster_id]
        diff = self.inputs.patches.get(cluster_id, "")
        problems = validate_patch(diff, cluster, cfg)
        if problems:
            # The fix job claimed success but the patch breaks policy: never push it.
            self._record("rejected", cluster_id, detail="; ".join(problems)[:1000])
            self.open_issue(
                cluster_id,
                "the proposed patch failed publish-time validation: " + "; ".join(problems)[:600],
                fix=fix,
            )
            return
        branch = cluster.branch
        if self._remote_branch_exists(branch):
            self._record("skipped", cluster_id, detail=f"{branch} already exists")
            return
        if not report.base_sha:
            raise PublishError("report.json has no base_sha")

        r = self.runner
        r.git("checkout", "-q", "--detach", report.base_sha)
        with tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False) as fh:
            fh.write(diff)
            patch_file = fh.name
        try:
            r.git("apply", "--check", "--whitespace=nowarn", patch_file)
            r.git("apply", "--index", "--whitespace=nowarn", patch_file)
        finally:
            os.unlink(patch_file)
        message = (
            f"{render.pr_title(cluster)}\n\n"
            f"Automated fix for secubot cluster {cluster.id}.\n"
            f"Finding: {', '.join(cluster.vuln_ids or cluster.cwes or cluster.rule_ids)[:200]}\n"
            f"Verified by: build, tests, re-scan ({', '.join(cluster.tools)}).\n"
        )
        r.env.update(self._ident_env())
        r.git("-c", "commit.gpgsign=false", "commit", "-q", "--no-verify", "-m", message)
        r.git("push", "origin", f"HEAD:refs/heads/{branch}", mutating=True)
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
            fh.write(
                render.pr_body(
                    cluster,
                    self.inputs.triage.get(cluster_id),
                    fix,
                    cfg.models.fix,
                    self.server,
                    self.repo,
                    self.run_id,
                )
            )
            body_file = fh.name
        try:
            args = [
                "pr",
                "create",
                "--draft",
                "--base",
                self.base_branch,
                "--head",
                branch,
                "--title",
                render.pr_title(cluster),
                "--body-file",
                body_file,
            ]
            for label in cfg.labels:
                args += ["--label", label]
            proc = r.gh(*args, mutating=True)
        finally:
            os.unlink(body_file)
        r.git("checkout", "-q", "--detach", report.base_sha)
        self._record("pull_request", cluster_id, url=proc.stdout.strip(), branch=branch)

    # -- issues ---------------------------------------------------------------------------

    def open_issue(self, cluster_id: str, reason: str, fix: FixResult | None = None) -> None:
        cluster = self.inputs.report.cluster(cluster_id)
        existing = self._open_issue_exists(cluster_id)
        if existing:
            self._record("skipped", cluster_id, detail=f"issue already open: {existing}")
            return
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
            fh.write(
                render.issue_body(
                    cluster,
                    reason,
                    self.inputs.triage.get(cluster_id),
                    fix,
                    self.cfg.models.triage,
                    self.server,
                    self.repo,
                    self.run_id,
                )
            )
            body_file = fh.name
        try:
            args = [
                "issue",
                "create",
                "--title",
                render.issue_title(cluster),
                "--body-file",
                body_file,
            ]
            for label in self.cfg.labels:
                args += ["--label", label]
            proc = self.runner.gh(*args, mutating=True)
        finally:
            os.unlink(body_file)
        self._record("issue", cluster_id, url=proc.stdout.strip(), detail=reason[:300])

    # -- state branch ---------------------------------------------------------------------

    def update_state(self, new: list[Suppression], today: dt.date, attempts: int = 2) -> None:
        r = self.runner
        for attempt in range(attempts):
            head = r.git(
                "ls-remote", "--heads", "origin", f"refs/heads/{STATE_BRANCH}", check=False
            ).stdout.split()
            parent = head[0] if head else None
            existing: list[Suppression] = []
            if parent:
                r.git("fetch", "-q", "--depth=1", "origin", f"refs/heads/{STATE_BRANCH}")
                shown = r.git("show", f"{parent}:{STATE_FILE}", check=False)
                existing = parse_state_suppressions(shown.stdout) if shown.returncode == 0 else []
            merged: dict[tuple, Suppression] = {}
            for s in [*existing, *new]:
                if s.active(today):
                    merged[(s.id, s.rule, s.path)] = s
            items = sorted(merged.values(), key=lambda s: (str(s.expires), s.id or ""))
            unchanged = items == sorted(existing, key=lambda s: (str(s.expires), s.id or ""))
            if unchanged and (parent or not items):
                return  # nothing to record
            blob = r.git(
                "hash-object", "-w", "--stdin", input=dump_state_suppressions(items)
            ).stdout.strip()
            readme = r.git("hash-object", "-w", "--stdin", input=STATE_README).stdout.strip()
            tree = r.git(
                "mktree",
                input=f"100644 blob {readme}\tREADME.md\n100644 blob {blob}\t{STATE_FILE}\n",
            ).stdout.strip()
            r.env.update(self._ident_env())
            commit_args = [
                "commit-tree",
                tree,
                "-m",
                f"secubot: {len(new)} new suppression(s), {len(items)} active",
            ]
            if parent:
                commit_args += ["-p", parent]
            commit = r.git(*commit_args).stdout.strip()
            pushed = r.git(
                "push", "origin", f"{commit}:refs/heads/{STATE_BRANCH}", check=False, mutating=True
            )
            if pushed.returncode == 0:
                self._record("state", "-", detail=f"{len(new)} new, {len(items)} active")
                return
            if attempt == attempts - 1:
                raise PublishError(f"could not update {STATE_BRANCH}: {pushed.stderr[-300:]}")

    # -- orchestration --------------------------------------------------------------------

    def run(self, today: dt.date | None = None) -> list[dict]:
        today = today or dt.date.today()
        inputs, cfg = self.inputs, self.cfg
        for why in inputs.ignored:
            self._record("ignored", "-", detail=why)
        if inputs.triage or inputs.fixes:
            self.ensure_labels()

        suppressions = [
            t.suppression
            for t in inputs.triage.values()
            if t.action == "suppress" and t.suppression is not None
        ]
        for t in inputs.triage.values():
            if t.action == "suppress":
                self._record("suppressed", t.cluster_id, detail=t.reason)
        self.update_state(suppressions, today)

        prs = 0
        for cid, fix in inputs.fixes.items():
            try:
                if fix.status == "fixed":
                    if prs >= cfg.policy.max_prs:
                        self._record("skipped", cid, detail="over policy.max_prs")
                        continue
                    self.open_pr(cid)
                    prs += 1
                elif fix.status in {"failed", "blocked"}:
                    self.open_issue(cid, f"automatic fix {fix.status}: {fix.reason}", fix=fix)
                else:
                    self._record("retry", cid, detail=f"fix error, retried next run: {fix.reason}")
            except (PublishError, KeyError) as exc:
                self._record("error", cid, detail=str(exc)[:500])

        for cid, t in inputs.triage.items():
            try:
                if t.action == "issue":
                    self.open_issue(cid, t.reason)
                elif t.action == "error":
                    self._record("retry", cid, detail=f"triage error, retried next run: {t.error}")
                elif t.action == "fix" and cid not in inputs.fixes:
                    self._record("deferred", cid, detail="no fix slot this run (policy.max_prs)")
            except (PublishError, KeyError) as exc:
                self._record("error", cid, detail=str(exc)[:500])
        return self.actions
