from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from secubot.config import SecfixConfig
from secubot.models import ScanReport
from secubot.normalise import normalise
from secubot.sarif import rewrite_uris

FIXTURES = Path(__file__).parent / "fixtures"
SARIF = FIXTURES / "sarif"
PROJECT = FIXTURES / "project"
PREFIX = {"govulncheck": "goapp", "gosec": "goapp", "bandit": "pyapp"}


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-C",
            str(cwd),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def prepare_sarif(root: Path, out: Path) -> list[Path]:
    """Rewrite the real scanner fixtures as the scan job would for a checkout at `root`."""
    out.mkdir(parents=True, exist_ok=True)
    files = []
    for f in sorted(SARIF.glob("*.sarif")):
        doc = json.loads(f.read_text().replace("file:///work/", root.as_uri() + "/"))
        doc = rewrite_uris(doc, root, prefix=PREFIX.get(f.stem, ""))
        target = out / f.name
        target.write_text(json.dumps(doc))
        files.append(target)
    return files


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(PROJECT, root)
    git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "init")
    return root.resolve()


@pytest.fixture
def cfg() -> SecfixConfig:
    return SecfixConfig()


@pytest.fixture
def report(project: Path, tmp_path: Path, cfg: SecfixConfig) -> ScanReport:
    files = prepare_sarif(project, tmp_path / "sarif")
    rep = normalise(files, project, cfg)
    rep.base_sha = git(project, "rev-parse", "HEAD").strip()
    return rep


def cluster_by(
    report: ScanReport,
    *,
    tool: str | None = None,
    path: str | None = None,
    line: int | None = None,
    package: str | None = None,
):
    for c in report.clusters:
        if tool and tool not in c.tools:
            continue
        if path and c.path != path:
            continue
        if line and c.start_line != line:
            continue
        if package and c.package != package:
            continue
        return c
    raise LookupError(f"no cluster for tool={tool} path={path} line={line} package={package}")
