"""Tool-permission gate for agent sessions (a PreToolUse hook).

This is the last line of defence inside the agent process, on top of:
  * Claude Code `--restricted` mode (file tools confined to the working directory),
  * an explicit `tools` list (tools not listed do not exist in the session),
  * `permission_mode="dontAsk"` (anything not pre-approved is denied),
  * no filesystem settings, no MCP servers, no CLAUDE.md.

The gate is deliberately simple and deny-by-default so it can be audited in one read. If
you run an external policy engine (e.g. a Veto-style tool-permission service), call it from
`Gate.check` — every tool call goes through here.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pathspec

READ_TOOLS = {"Read", "Grep", "Glob"}
EDIT_TOOLS = {"Edit", "MultiEdit"}
WRITE_TOOLS = {"Write"}
SHELL_METACHARS = re.compile(r"[;&|`$<>(){}\[\]\\\n\r*?!#~'\"]")


@dataclass
class GatePolicy:
    root: Path
    allow_edit: bool = False
    allow_write: bool = False
    bash_commands: list[str] = field(default_factory=list)
    """Exact commands, or `prefix:*` entries (prefix match, shell metacharacters refused)."""
    protected: pathspec.PathSpec = field(
        default_factory=lambda: pathspec.PathSpec.from_lines("gitignore", [])
    )

    @property
    def tools(self) -> list[str]:
        tools = sorted(READ_TOOLS)
        if self.allow_edit:
            tools.append("Edit")
        if self.allow_write:
            tools.append("Write")
        if self.bash_commands:
            tools.append("Bash")
        return tools

    @property
    def allowed_tools(self) -> list[str]:
        """Permission rules handed to Claude Code (the gate re-checks every call)."""
        allowed = [t for t in self.tools if t != "Bash"]
        for cmd in self.bash_commands:
            allowed.append(f"Bash({cmd})")
        return allowed


@dataclass
class GateDecision:
    allowed: bool
    reason: str = ""


@dataclass
class Gate:
    policy: GatePolicy
    log: list[dict[str, Any]] = field(default_factory=list)

    # -- path checks ------------------------------------------------------------------------

    def _inside_root(self, raw: str | None) -> tuple[bool, str]:
        if not raw:
            return True, ""
        root = self.policy.root.resolve()
        p = Path(raw)
        if not p.is_absolute():
            p = root / p
        # realpath resolves symlinks, so `link -> /proc/self/environ` is caught
        real = Path(os.path.realpath(p))
        try:
            rel = real.relative_to(root).as_posix()
        except ValueError:
            return False, f"path outside the repository: {raw}"
        if rel == ".git" or rel.startswith(".git/"):
            return False, "the .git directory is off limits"
        return True, rel

    def _check_path(self, raw: str | None, *, write: bool) -> GateDecision:
        ok, rel_or_reason = self._inside_root(raw)
        if not ok:
            return GateDecision(False, rel_or_reason)
        if write:
            rel = rel_or_reason
            if not rel:
                return GateDecision(False, "missing file path")
            if self.policy.protected.match_file(rel):
                return GateDecision(False, f"{rel} is a protected path")
        return GateDecision(True)

    # -- bash -------------------------------------------------------------------------------

    def _check_bash(self, command: str) -> GateDecision:
        cmd = command.strip()
        for allowed in self.policy.bash_commands:
            if allowed.endswith(":*"):
                prefix = allowed[:-2].strip()
                if (cmd == prefix or cmd.startswith(prefix + " ")) and not SHELL_METACHARS.search(
                    cmd
                ):
                    return GateDecision(True)
            elif cmd == allowed.strip():
                return GateDecision(True)
        allowed_list = ", ".join(self.policy.bash_commands) or "none"
        return GateDecision(False, f"command not allowed. Allowed commands: {allowed_list}")

    # -- entry point ------------------------------------------------------------------------

    def check(self, tool_name: str, tool_input: dict[str, Any]) -> GateDecision:
        decision = self._check(tool_name, tool_input or {})
        self.log.append(
            {
                "tool": tool_name,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "input": _summarise(tool_name, tool_input or {}),
            }
        )
        return decision

    def _check(self, tool_name: str, ti: dict[str, Any]) -> GateDecision:
        if tool_name == "Read":
            return self._check_path(ti.get("file_path"), write=False)
        if tool_name == "Grep":
            return self._check_path(ti.get("path"), write=False)
        if tool_name == "Glob":
            pattern = str(ti.get("pattern", ""))
            if pattern.startswith("/") or ".." in Path(pattern).parts:
                return GateDecision(False, "glob patterns must be relative to the repository")
            return self._check_path(ti.get("path"), write=False)
        if tool_name in EDIT_TOOLS:
            if not self.policy.allow_edit:
                return GateDecision(False, "editing is not allowed in this phase")
            return self._check_path(ti.get("file_path"), write=True)
        if tool_name in WRITE_TOOLS:
            if not self.policy.allow_write:
                return GateDecision(False, "creating files is not allowed (fix.allow_new_files)")
            return self._check_path(ti.get("file_path"), write=True)
        if tool_name == "Bash":
            if not self.policy.bash_commands:
                return GateDecision(False, "no shell access in this phase")
            return self._check_bash(str(ti.get("command", "")))
        return GateDecision(False, f"tool {tool_name} is not permitted")

    def written_files(self) -> list[str]:
        files = []
        for entry in self.log:
            if entry["allowed"] and entry["tool"] in WRITE_TOOLS | EDIT_TOOLS:
                files.append(entry["input"])
        return sorted(set(files))

    def hook(self):
        """Return an async PreToolUse hook callback for claude-agent-sdk."""

        async def pre_tool_use(input_data: dict[str, Any], tool_use_id: str | None, context: Any):
            decision = self.check(input_data.get("tool_name", ""), input_data.get("tool_input", {}))
            if decision.allowed:
                return {}
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"secubot gate: {decision.reason}",
                }
            }

        return pre_tool_use


def _summarise(tool: str, ti: dict[str, Any]) -> str:
    if tool == "Bash":
        return str(ti.get("command", ""))[:300]
    for key in ("file_path", "path", "pattern"):
        if key in ti:
            return str(ti[key])[:300]
    return ""
