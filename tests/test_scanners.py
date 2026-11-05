from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

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
    stage_line,
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


DOCKERFILE = """# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
RUN go build ./...

from --platform=$BUILDPLATFORM python:3.12-slim As All-In-One
COPY --from=build /app /app

FROM gcr.io/distroless/static-debian12:nonroot
"""


def _image_sarif(path):
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Trivy", "rules": []}},
                        "results": [
                            {
                                "ruleId": "CVE-2026-0001",
                                "message": {"text": "openssl"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "usr/lib/libssl.so"},
                                            "region": {"startLine": 7},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
    )


def _fake_docker_and_trivy(calls):
    def fake_run(cmd, cwd, timeout=1800, **kw):
        calls.append(cmd)
        if cmd[:2] == ["trivy", "image"]:
            _image_sarif(Path(cmd[cmd.index("--output") + 1]))
        return True, ""

    return fake_run


@pytest.mark.parametrize("target", [None, "all-in-one"])
def test_trivy_image_build_target(project, tmp_path, monkeypatch, target):
    (project / "Dockerfile").write_text(DOCKERFILE)
    calls: list[list[str]] = []
    monkeypatch.setattr("secubot.scanners._run", _fake_docker_and_trivy(calls))
    image_cfg = {"enabled": True, **({"target": target} if target else {})}
    cfg = SecfixConfig.model_validate({"scanners": {"trivy_image": image_cfg}})
    status = run_scanner("trivy-image", project, tmp_path / "out", cfg)
    assert status.ok, status.detail
    build = calls[0]
    assert build[:2] == ["docker", "build"]
    assert build[-1] == "."  # the context stays last
    if target:
        assert "--target=all-in-one" in build
    else:
        assert not any(a.startswith("--target") for a in build)
    doc = json.loads((tmp_path / "out" / "trivy-image.sarif").read_text())
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "Dockerfile"
    # with a target: the stage's FROM line; without: line 1, as before
    assert loc["region"] == {"startLine": 5 if target else 1}


def test_stage_line(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text(DOCKERFILE)
    assert stage_line(df, "build") == 2
    assert stage_line(df, "all-in-one") == 5  # case-insensitive, --platform flag
    assert stage_line(df, "missing") == 1
    assert stage_line(tmp_path / "nope", "build") == 1
