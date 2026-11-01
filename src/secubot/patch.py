"""Patch validation — run in the fix job (fast feedback to the agent) and again, as the
actual trust boundary, in the publish job before anything is pushed.

The publish job treats the patch as hostile: it was produced by an agent that read
prompt-injectable content, inside a job that executed repository code.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from secubot.config import SecfixConfig
from secubot.models import Cluster

SECRET_PATTERNS = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Slack token", re.compile(r"\bxox[abpors]-[A-Za-z0-9-]{10,}")),
]
SECRET_ENV_VARS = ["ANTHROPIC_API_KEY", "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN"]


@dataclass
class FileChange:
    path: str
    old_path: str | None = None
    added: int = 0
    removed: int = 0
    new_file: bool = False
    deleted: bool = False
    binary: bool = False
    mode: str | None = None
    added_lines: list[str] = field(default_factory=list)


def parse_diff(diff: str) -> list[FileChange]:
    changes: list[FileChange] = []
    cur: FileChange | None = None
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            m = re.match(r'diff --git "?a/(.+?)"? "?b/(.+?)"?$', line)
            a, b = (m.group(1), m.group(2)) if m else ("", line.split(" b/", 1)[-1])
            cur = FileChange(path=b, old_path=a if a != b else None)
            changes.append(cur)
            continue
        if cur is None:
            continue
        if line.startswith("new file mode"):
            cur.new_file = True
            cur.mode = line.split()[-1]
        elif line.startswith("deleted file mode"):
            cur.deleted = True
        elif line.startswith(("new mode", "old mode")):
            cur.mode = line.split()[-1]
        elif line.startswith(("Binary files", "GIT binary patch")):
            cur.binary = True
        elif line.startswith(("rename from", "rename to", "copy from", "copy to")):
            cur.old_path = cur.old_path or line.split(" ", 2)[-1]
        elif line.startswith("+++ ") or line.startswith("--- "):
            continue
        elif line.startswith("+"):
            cur.added += 1
            cur.added_lines.append(line[1:])
        elif line.startswith("-"):
            cur.removed += 1
    return changes


def validate_patch(diff: str, cluster: Cluster, cfg: SecfixConfig) -> list[str]:
    """Return a list of violations; empty means the patch may be published."""
    problems: list[str] = []
    changes = parse_diff(diff)
    if not diff.strip() or not changes:
        return ["the patch is empty: nothing was changed"]

    protected = cfg.protected_spec()
    sensitive = cfg.sensitive_spec()
    finding_paths = set(cluster.paths)
    total = 0
    for ch in changes:
        for p in filter(None, {ch.path, ch.old_path}):
            if p.startswith("/") or ".." in p.split("/"):
                problems.append(f"{p}: path escapes the repository")
            if protected.match_file(p):
                problems.append(f"{p}: protected path (CI, agent or pipeline configuration)")
            if sensitive.match_file(p) and p not in finding_paths:
                problems.append(
                    f"{p}: auth/crypto/session code may only change when the finding is there"
                )
        if ch.deleted:
            problems.append(f"{ch.path}: deleting files is not allowed")
        if ch.binary:
            problems.append(f"{ch.path}: binary changes are not allowed")
        if ch.mode in {"120000", "160000"}:
            problems.append(f"{ch.path}: symlinks and submodules are not allowed")
        elif ch.mode == "100755" and not ch.new_file:
            problems.append(f"{ch.path}: making files executable is not allowed")
        if ch.new_file and not cfg.fix.allow_new_files:
            problems.append(f"{ch.path}: new files are not allowed (fix.allow_new_files)")
        if ch.old_path and not ch.deleted and not ch.new_file:
            problems.append(f"{ch.path}: renames are not allowed")
        total += ch.added + ch.removed
        for added in ch.added_lines:
            for label, rx in SECRET_PATTERNS:
                if rx.search(added):
                    problems.append(f"{ch.path}: added line looks like a {label}")
            for var in SECRET_ENV_VARS:
                value = os.environ.get(var)
                if value and len(value) >= 12 and value in added:
                    problems.append(f"{ch.path}: added line contains the value of ${var}")
    if len(changes) > cfg.fix.max_changed_files:
        problems.append(
            f"{len(changes)} files changed, more than fix.max_changed_files="
            f"{cfg.fix.max_changed_files}"
        )
    if total > cfg.fix.max_changed_lines:
        problems.append(
            f"{total} lines changed, more than fix.max_changed_lines={cfg.fix.max_changed_lines}"
        )
    return sorted(set(problems))


def diffstat(diff: str) -> str:
    rows = [f"{ch.path} | +{ch.added} -{ch.removed}" for ch in parse_diff(diff)]
    return "\n".join(rows)
