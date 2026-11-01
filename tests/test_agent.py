from __future__ import annotations

from pathlib import Path

from secubot.agent import AGENT_ENV, SessionSpec, _parse_json_text, build_options
from secubot.gate import Gate, GatePolicy


def test_options_are_hardened(tmp_path: Path):
    gate = Gate(GatePolicy(root=tmp_path, allow_edit=True, bash_commands=["make test"]))
    spec = SessionSpec(
        cwd=tmp_path,
        model="claude-opus-5-5",
        system_append="rules",
        gate=gate,
        output_schema={"type": "object"},
        max_turns=7,
        max_budget_usd=1.5,
        effort="high",
        extra_env={"X": "1"},
    )
    o = build_options(spec)
    assert o.tools == ["Glob", "Grep", "Read", "Edit", "Bash"]
    assert "Bash(make test)" in o.allowed_tools and "Bash" not in o.allowed_tools
    assert {"WebFetch", "WebSearch", "Task"} <= set(o.disallowed_tools)
    assert o.permission_mode == "default"
    assert o.setting_sources == []
    assert o.strict_mcp_config is True and o.mcp_servers == {}
    assert o.extra_args == {"restricted": None}
    assert o.system_prompt == {"type": "preset", "preset": "claude_code", "append": "rules"}
    assert o.env["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1" and o.env["X"] == "1"
    assert set(AGENT_ENV) <= set(o.env)
    assert o.max_turns == 7 and o.max_budget_usd == 1.5 and o.effort == "high"
    assert o.output_format == {"type": "json_schema", "schema": {"type": "object"}}
    assert "StructuredOutput" in o.allowed_tools
    assert len(o.hooks["PreToolUse"]) == 1


def test_json_fallback_parser():
    assert _parse_json_text('{"a": 1}') == {"a": 1}
    assert _parse_json_text('Here you go:\n```json\n{"a": 2}\n```') == {"a": 2}
    assert _parse_json_text('text {"a": {"b": 3}} trailing') == {"a": {"b": 3}}
    assert _parse_json_text("no json") is None
