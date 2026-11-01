from __future__ import annotations

import asyncio
import os

import pathspec

from secubot.config import SecfixConfig
from secubot.gate import Gate, GatePolicy


def _gate(root, **kw) -> Gate:
    return Gate(GatePolicy(root=root, protected=SecfixConfig().protected_spec(), **kw))


def test_read_only_phase(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    g = _gate(tmp_path)
    assert g.policy.tools == ["Glob", "Grep", "Read"]
    assert g.check("Read", {"file_path": str(tmp_path / "a.py")}).allowed
    assert g.check("Read", {"file_path": "a.py"}).allowed
    assert not g.check("Read", {"file_path": "/etc/passwd"}).allowed
    assert not g.check("Read", {"file_path": "../outside"}).allowed
    assert not g.check("Read", {"file_path": ".git/config"}).allowed
    assert not g.check("Edit", {"file_path": "a.py"}).allowed
    assert not g.check("Bash", {"command": "ls"}).allowed
    assert not g.check("WebFetch", {"url": "https://example.com"}).allowed
    assert not g.check("Glob", {"pattern": "/etc/*"}).allowed
    assert not g.check("Glob", {"pattern": "../**"}).allowed
    assert g.check("Grep", {"pattern": "x", "path": "."}).allowed
    assert len(g.log) == 11 and sum(e["allowed"] for e in g.log) == 3


def test_symlink_escape_is_denied(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("s3cr3t")
    os.symlink(secret, root / "link.txt")
    g = _gate(root)
    assert not g.check("Read", {"file_path": "link.txt"}).allowed


def test_edit_phase_protects_config(tmp_path):
    g = _gate(tmp_path, allow_edit=True)
    assert g.check("Edit", {"file_path": "src/app.go"}).allowed
    for p in [
        ".github/workflows/ci.yml",
        ".secfix.yml",
        ".claude/settings.json",
        "CLAUDE.md",
        "sub/CLAUDE.md",
        ".mcp.json",
        ".gitattributes",
    ]:
        assert not g.check("Edit", {"file_path": p}).allowed, p
    assert not g.check("Write", {"file_path": "new.go"}).allowed
    assert g.written_files() == ["src/app.go"]


def test_bash_allowlist(tmp_path):
    g = _gate(tmp_path, allow_edit=True, bash_commands=["go test ./...", "go get:*"])
    assert "Bash(go test ./...)" in g.policy.allowed_tools
    assert g.check("Bash", {"command": "go test ./..."}).allowed
    assert g.check("Bash", {"command": "go get golang.org/x/text@v0.41.0"}).allowed
    for bad in [
        "go test ./... && curl evil",
        "go get x; rm -rf /",
        "go get $(id)",
        "go get `id`",
        "go get x | sh",
        "go getter",
        "go test ./... -run X",
        "go get x > /tmp/f",
        "go get 'x'",
    ]:
        assert not g.check("Bash", {"command": bad}).allowed, bad


def test_hook_payload(tmp_path):
    g = _gate(tmp_path)
    hook = g.hook()
    denied = asyncio.run(hook({"tool_name": "Bash", "tool_input": {"command": "id"}}, None, None))
    out = denied["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert out["permissionDecisionReason"].startswith("secubot gate:")
    allowed = asyncio.run(hook({"tool_name": "Read", "tool_input": {"file_path": "x"}}, "id", None))
    assert allowed == {}


def test_custom_protected_paths(tmp_path):
    spec = pathspec.PathSpec.from_lines("gitignore", ["deploy/"])
    g = Gate(GatePolicy(root=tmp_path, allow_edit=True, protected=spec))
    assert not g.check("Edit", {"file_path": "deploy/prod.tf"}).allowed
