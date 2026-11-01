from __future__ import annotations

import json
import os
import shutil

import pytest

from secubot.config import SecfixConfig
from secubot.normalise import normalise
from secubot.scanners import (
    _fully_pinned,
    _skip_dirs,
    _unreadable,
    enabled_tools,
    run_scanner,
    scrubbed_env,
)


def test_enabled_tools(project):
    assert enabled_tools(project, SecfixConfig()) == [
        "trivy-fs",
        "govulncheck",
        "gosec",
        "bandit",
        "pip-audit",
        "semgrep",
    ]
    cfg = SecfixConfig.model_validate(
        {
            "languages": ["python"],
            "scanners": {"semgrep": {"enabled": False}, "trivy_image": {"enabled": True}},
        }
    )
    assert enabled_tools(project, cfg) == ["trivy-fs", "trivy-image", "bandit", "pip-audit"]


def test_skip_dirs_only_literal_prefixes():
    cfg = SecfixConfig.model_validate(
        {"paths": {"skip": ["vendor/", "**/testdata/", "!keep/", "docs"]}}
    )
    assert _skip_dirs(cfg) == ["vendor", "docs"]


def test_fully_pinned(tmp_path):
    f = tmp_path / "r.txt"
    f.write_text("requests==2.19.0  # pinned\nPyYAML==5.3\n\n")
    assert _fully_pinned(f)
    f.write_text("requests>=2\n")
    assert not _fully_pinned(f)
    f.write_text("-r other.txt\nrequests==1\n")
    assert not _fully_pinned(f)


def test_scrubbed_env(monkeypatch):
    for k in [
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
    ]:
        monkeypatch.setenv(k, "secret")
    monkeypatch.setenv("PATH_EXTRA", "kept")
    env = scrubbed_env()
    assert env["PATH_EXTRA"] == "kept"
    assert not {
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
    } & set(env)


def test_missing_scanner_is_reported(project, tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    status = run_scanner("gosec", project, tmp_path / "out", SecfixConfig())
    assert not status.ok and "not installed" in status.detail


@pytest.mark.skipif(shutil.which("bandit") is None, reason="bandit not installed")
def test_bandit_end_to_end(project, tmp_path):
    cfg = SecfixConfig()
    status = run_scanner("bandit", project, tmp_path / "out", cfg)
    assert status.ok, status.detail
    doc = json.loads((tmp_path / "out" / "bandit.sarif").read_text())
    uris = {
        loc["physicalLocation"]["artifactLocation"]["uri"]
        for r in doc["runs"][0]["results"]
        for loc in r["locations"]
    }
    assert uris == {"pyapp/app.py"}
    report = normalise([tmp_path / "out" / "bandit.sarif"], project, cfg)
    assert any("CWE-78" in c.cwes for c in report.clusters)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can open anything")
def test_unreadable_paths_are_found(tmp_path):
    # Inside Claude Code's sandbox (`secubot recheck`), masked config files can't be opened
    # and trivy aborts the whole scan on them (second rami run).
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / ".mcp.json").write_text("{}")
    (tmp_path / ".mcp.json").chmod(0)
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude").chmod(0)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("")
    (tmp_path / "node_modules" / "x.js").chmod(0)
    os.mkfifo(tmp_path / "pipe")  # must not block
    try:
        files, dirs = _unreadable(tmp_path, ["node_modules"])
    finally:
        (tmp_path / ".claude").chmod(0o755)
    assert files == [".mcp.json"]
    assert dirs == [".claude"]
