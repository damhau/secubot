"""Claude Code (via claude-agent-sdk) session wrapper with the hardening applied in one place.

Every session — triage or fix — is started here, so the isolation settings cannot drift
between phases:

  * `--restricted`: file tools confined to the repository, code-running tools absent unless
    explicitly listed, user/project/local settings files ignored;
  * `setting_sources=[]`: no `.claude/settings.json`, no hooks, no CLAUDE.md from the repo;
  * `strict_mcp_config` + no servers: a repo-supplied `.mcp.json` is never loaded;
  * explicit `tools` list + `permission_mode="dontAsk"` + the PreToolUse gate;
  * `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1`: Anthropic/cloud credentials are stripped from the
    environment of anything the Bash tool runs;
  * non-essential traffic disabled, so the only endpoint needed is the Anthropic API.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from secubot.gate import Gate

DISALLOWED_TOOLS = [
    "WebFetch",
    "WebSearch",
    "Task",
    "Agent",
    "NotebookEdit",
    "Skill",
    "SlashCommand",
    "KillShell",
    "BashOutput",
]

AGENT_ENV = {
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_AUTOUPDATER": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
}


@dataclass
class TurnResult:
    text: str = ""
    structured: dict[str, Any] | None = None
    is_error: bool = False
    error: str = ""
    cost_usd: float = 0.0
    num_turns: int = 0
    session_id: str = ""
    stop: str = ""


@dataclass
class SessionSpec:
    cwd: Path
    model: str
    system_append: str
    gate: Gate
    output_schema: dict[str, Any] | None = None
    max_turns: int = 40
    max_budget_usd: float = 5.0
    effort: str = "high"
    extra_env: dict[str, str] = field(default_factory=dict)


class AgentSession(Protocol):
    """What triage and fix need from an agent; tests substitute a fake."""

    async def turn(self, prompt: str) -> TurnResult: ...

    async def close(self) -> None: ...


class AgentFactory(Protocol):
    def __call__(self, spec: SessionSpec) -> AgentSession: ...


def build_options(spec: SessionSpec):
    """Build ClaudeAgentOptions. Kept separate so the hardening is unit-testable."""
    from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

    policy = spec.gate.policy
    options = ClaudeAgentOptions(
        cwd=str(spec.cwd),
        model=spec.model,
        tools=policy.tools,
        allowed_tools=policy.allowed_tools,
        disallowed_tools=list(DISALLOWED_TOOLS),
        permission_mode="dontAsk",
        setting_sources=[],
        strict_mcp_config=True,
        mcp_servers={},
        system_prompt={"type": "preset", "preset": "claude_code", "append": spec.system_append},
        hooks={"PreToolUse": [HookMatcher(matcher=None, hooks=[spec.gate.hook()])]},
        max_turns=spec.max_turns,
        max_budget_usd=spec.max_budget_usd,
        effort=spec.effort,
        env={**AGENT_ENV, **spec.extra_env},
        extra_args={"restricted": None},
    )
    if spec.output_schema is not None:
        options.output_format = {"type": "json_schema", "schema": spec.output_schema}
    return options


def _parse_json_text(text: str) -> dict[str, Any] | None:
    """Fallback when structured output is unavailable: last JSON object in the text."""
    text = text.strip()
    for candidate in (text, text.split("```json")[-1].split("```")[0] if "```" in text else ""):
        candidate = candidate.strip()
        if candidate.startswith("{"):
            try:
                value = json.loads(candidate)
                return value if isinstance(value, dict) else None
            except json.JSONDecodeError:
                continue
    start, end = text.rfind("{"), text.rfind("}")
    while start != -1 and end > start:
        try:
            value = json.loads(text[start : end + 1])
            return value if isinstance(value, dict) else None
        except json.JSONDecodeError:
            start = text.rfind("{", 0, start)
    return None


class ClaudeSession:
    """One multi-turn Claude Code conversation (the fix loop resumes it with feedback)."""

    def __init__(self, spec: SessionSpec):
        self.spec = spec
        self._client = None

    async def _ensure(self):
        if self._client is None:
            from claude_agent_sdk import ClaudeSDKClient

            self._client = ClaudeSDKClient(options=build_options(self.spec))
            await self._client.connect()
        return self._client

    async def turn(self, prompt: str) -> TurnResult:
        from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock

        client = await self._ensure()
        await client.query(prompt)
        texts: list[str] = []
        result = TurnResult()
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                texts.extend(b.text for b in message.content if isinstance(b, TextBlock))
            elif isinstance(message, ResultMessage):
                result.is_error = bool(message.is_error)
                result.error = "; ".join(message.errors or []) or (
                    message.subtype if message.is_error else ""
                )
                result.cost_usd = float(message.total_cost_usd or 0.0)
                result.num_turns = int(message.num_turns or 0)
                result.session_id = message.session_id
                result.stop = str(message.terminal_reason or message.subtype or "")
                if isinstance(message.structured_output, dict):
                    result.structured = message.structured_output
                if message.result:
                    texts.append(message.result)
        result.text = "\n".join(t for t in texts if t).strip()
        if result.structured is None and self.spec.output_schema is not None:
            result.structured = _parse_json_text(result.text)
        return result

    async def close(self) -> None:
        if self._client is not None:
            await self._client.disconnect()
            self._client = None


def claude_session(spec: SessionSpec) -> AgentSession:
    return ClaudeSession(spec)
