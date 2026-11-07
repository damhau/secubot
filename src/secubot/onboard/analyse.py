"""What `secubot onboard` learns from a clone of the target repository.

Reuses the pipeline's own detection (`secubot.config`), so the wizard and the scan job agree
on what a Go, Python or Node project is.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from secubot.config import (
    NODE_LOCKFILES,
    SecfixConfig,
    go_modules,
    node_package_manager,
    node_projects,
    python_projects,
)

CALLER_MARKER = "/.github/workflows/secfix.yml@"
DEPENDABOT_FILES = (".github/dependabot.yml", ".github/dependabot.yaml")
RENOVATE_FILES = (
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".renovaterc.json5",
    ".github/renovate.json",
    ".github/renovate.json5",
)
NPM_DEFAULT_TEST = 'echo "Error: no test specified" && exit 1'
# Browser suites need a running app and browsers, so they can't verify a fix on a fresh runner.
BROWSER_TESTS = re.compile(r"\b(playwright|cypress)\b")


@dataclass
class Project:
    kind: str
    """go | python | node"""
    path: str
    """Repository-relative directory, "" for the root."""
    manager: str
    """go | uv | poetry | pip | npm | pnpm | yarn | yarn-berry | bun"""
    has_tests: bool = False
    typescript: bool = False
    scripts: dict[str, str] = field(default_factory=dict)
    """package.json scripts (Node only)."""
    locked: bool = True
    """Node only: a lock file exists here or in a parent (else a frozen install fails)."""
    requirements: str = ""
    """pip only: the requirements file to install, "" when the project installs itself."""

    @property
    def label(self) -> str:
        lang = {"go": "Go", "python": "Python", "node": "Node"}[self.kind]
        if self.typescript:
            lang = "TypeScript"
        return f"{lang} ({self.manager}) in {self.path or '/'}"


@dataclass
class RepoFacts:
    projects: list[Project]
    docker_dirs: list[str]
    caller: str | None
    """An existing workflow that already calls secubot."""
    secfix_config: bool
    dependabot_config: str | None
    renovate_config: str | None
    node_roots: dict[str, str] = field(default_factory=dict)
    """Directory -> package manager, for each Node lock file (or lock-less project)."""

    def primary(self, kind: str) -> Project | None:
        """The project the build/test commands target: the top-most, then one with tests."""
        found = [p for p in self.projects if p.kind == kind]
        if not found:
            return None
        return min(found, key=lambda p: (len(Path(p.path).parts), not p.has_tests, p.path))

    @property
    def kinds(self) -> list[str]:
        return [k for k in ("go", "python", "node") if self.primary(k)]


def _rel(path: Path, root: Path) -> str:
    rel = path.relative_to(root).as_posix()
    return "" if rel == "." else rel


def _walk(root: Path, cfg: SecfixConfig):
    skip = cfg.skip_spec()
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = _rel(Path(dirpath), root)
        prefix = f"{rel_dir}/" if rel_dir else ""
        dirnames[:] = sorted(
            d for d in dirnames if d != ".git" and not skip.match_file(f"{prefix}{d}/")
        )
        yield Path(dirpath), prefix, filenames


def _has_files(root: Path, cfg: SecfixConfig, match) -> bool:
    return any(any(match(name) for name in names) for _, _, names in _walk(root, cfg))


def _python_project(root: Path, d: Path, cfg: SecfixConfig) -> Project:
    if (d / "uv.lock").is_file():
        manager = "uv"
    elif (d / "poetry.lock").is_file():
        manager = "poetry"
    else:
        manager = "pip"
    requirements = ""
    if manager == "pip" and not ((d / "pyproject.toml").is_file() or (d / "setup.py").is_file()):
        reqs = sorted(p.name for p in d.glob("requirements*.txt"))
        requirements = "requirements.txt" if "requirements.txt" in reqs else (reqs or [""])[0]
    pyproject = (
        (d / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
        if (d / "pyproject.toml").is_file()
        else ""
    )
    has_tests = (
        (d / "tests").is_dir()
        or (d / "test").is_dir()
        or (d / "conftest.py").is_file()
        or "[tool.pytest" in pyproject
        or _has_files(d, cfg, lambda n: n.startswith("test_") and n.endswith(".py"))
    )
    return Project("python", _rel(d, root), manager, has_tests=has_tests, requirements=requirements)


def _node_project(root: Path, d: Path) -> Project:
    try:
        manifest = json.loads((d / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = {}
    manifest = manifest if isinstance(manifest, dict) else {}
    scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    deps: dict = {}
    for key in ("dependencies", "devDependencies"):
        if isinstance(manifest.get(key), dict):
            deps.update(manifest[key])
    test = str(scripts.get("test", "")).strip()
    return Project(
        "node",
        _rel(d, root),
        node_package_manager(d, root),
        has_tests=bool(test) and test != NPM_DEFAULT_TEST and not BROWSER_TESTS.search(test),
        typescript=(d / "tsconfig.json").is_file() or "typescript" in deps,
        scripts={str(k): str(v) for k, v in scripts.items()},
        locked=_lock_owner(root, d) is not None,
    )


def _lock_owner(root: Path, d: Path) -> Path | None:
    """The nearest directory, from `d` up to the root, holding a Node lock file."""
    while True:
        if any((d / lock).is_file() for lock in NODE_LOCKFILES):
            return d
        if d == root or d.parent == d:
            return None
        d = d.parent


def _is_dockerfile(name: str) -> bool:
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


def _node_roots(root: Path, projects: list[Project]) -> dict[str, str]:
    """Where Dependabot should look for Node: the directory of each lock file.

    A workspace keeps one lock file at its root and Dependabot updates every package from
    there, so the packages under it aren't listed separately. A project with no lock file
    anywhere above it is listed as itself.
    """
    roots: dict[str, str] = {}
    for project in projects:
        owner = _lock_owner(root, root / project.path) or root / project.path
        roots.setdefault(_rel(owner, root), node_package_manager(owner, root))
    return dict(sorted(roots.items()))


def analyse(root: Path) -> RepoFacts:
    cfg = SecfixConfig()
    projects: list[Project] = []
    for d in go_modules(root, cfg):
        has_tests = _has_files(d, cfg, lambda n: n.endswith("_test.go"))
        projects.append(Project("go", _rel(d, root), "go", has_tests=has_tests))
    projects += [_python_project(root, d, cfg) for d in python_projects(root, cfg)]
    projects += [_node_project(root, d) for d in node_projects(root, cfg)]

    docker_dirs = sorted(
        {_rel(d, root) for d, _, names in _walk(root, cfg) if any(map(_is_dockerfile, names))}
    )

    caller = None
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        for wf in sorted(workflows.glob("*.y*ml")):
            text = wf.read_text(encoding="utf-8", errors="replace")
            if "secubot" in text and CALLER_MARKER in text:
                caller = _rel(wf, root)
                break

    return RepoFacts(
        node_roots=_node_roots(root, [p for p in projects if p.kind == "node"]),
        projects=projects,
        docker_dirs=docker_dirs,
        caller=caller,
        secfix_config=(root / ".secfix.yml").is_file(),
        dependabot_config=next((f for f in DEPENDABOT_FILES if (root / f).is_file()), None),
        renovate_config=next((f for f in RENOVATE_FILES if (root / f).is_file()), None),
    )
