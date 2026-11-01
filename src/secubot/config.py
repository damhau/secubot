"""`.secfix.yml` — the per-repository configuration file (about 10 lines in most repos)."""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
from typing import Literal

import pathspec
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secubot.models import Kind, Severity

DEFAULT_CONFIG_PATH = ".secfix.yml"
DEFAULT_MODEL = "claude-opus-5-5"

# Paths the agent may never modify and the publish job refuses in a patch, whatever the
# repository configuration says. These either execute in CI, configure the agent, or
# configure this pipeline.
BUILTIN_PROTECTED_PATHS = [
    ".git/",
    ".github/",
    ".gitmodules",
    ".gitattributes",
    ".secfix.yml",
    ".secfix/",
    ".claude/",
    ".mcp.json",
    "CLAUDE.md",
    "CLAUDE.local.md",
    "**/CLAUDE.md",
    "AGENTS.md",
    ".devcontainer/",
    ".vscode/",
    ".idea/",
    ".pre-commit-config.yaml",
    ".gitlab-ci.yml",
    "CODEOWNERS",
    "**/CODEOWNERS",
]

DEFAULT_SENSITIVE_PATHS = [
    "**/auth/**",
    "**/authn/**",
    "**/authz/**",
    "**/*auth*.*",
    "**/crypto/**",
    "**/*crypto*.*",
    "**/security/**",
    "**/session*/**",
    "**/*session*.*",
    "**/oauth*/**",
    "**/jwt*/**",
]

DEFAULT_SKIP_PATHS = [
    ".git/",
    "vendor/",
    "node_modules/",
    "third_party/",
    ".venv/",
    "venv/",
    "**/testdata/",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Paths(_Strict):
    skip: list[str] = Field(default_factory=lambda: list(DEFAULT_SKIP_PATHS))
    """gitignore-style patterns; findings under them are dropped and scanners skip them."""
    ignore_protected: bool = False
    """Drop findings in protected paths (GitHub Actions workflows, agent config) from secubot's
    report. They are still scanned and still uploaded to Code Scanning."""


class Commands(_Strict):
    setup: str | None = None
    """Runs once before the agent starts (e.g. `uv sync --frozen`, `go mod download`)."""
    build: str | None = None
    test: str | None = None
    timeout_minutes: int = Field(default=20, ge=1, le=120)


class SemgrepConfig(_Strict):
    enabled: bool = True
    configs: list[str] = Field(default_factory=lambda: ["p/default"])


class TrivyImageConfig(_Strict):
    enabled: bool = False
    dockerfile: str = "Dockerfile"
    context: str = "."


class Scanners(_Strict):
    trivy: bool = True
    trivy_image: TrivyImageConfig = Field(default_factory=TrivyImageConfig)
    govulncheck: bool = True
    gosec: bool = True
    bandit: bool = True
    pip_audit: bool = True
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)


class Policy(_Strict):
    min_severity: Severity = Severity.MEDIUM
    max_triage: int = Field(default=5, ge=0, le=50)
    """How many clusters are triaged per run (top N by severity and reachability)."""
    max_prs: int = Field(default=3, ge=0, le=20)
    """How many fix attempts (and therefore PRs) per run."""
    kinds: list[Kind] = Field(
        default_factory=lambda: [Kind.CODE, Kind.DEPENDENCY, Kind.IAC, Kind.SECRET]
    )
    skip_unreachable: bool = True
    """Drop dependency findings that govulncheck proved are not called."""
    dependencies: Literal["all", "breaking-only", "none"] = "breaking-only"
    """`breaking-only` leaves simple bumps to Renovate/Dependabot and only takes upgrades that
    cross a major version (or 0.x minor) or have no fixed version but are reachable."""
    bump_uncertain_dependencies: bool = True
    """When triage can't settle a dependency finding, still try the upgrade (draft PR, verified
    by build/test/rescan) if it is non-breaking and has a fixed version. Otherwise: an issue."""
    auto_suppress: bool = True
    """Record agreed false positives in the state branch instead of opening anything."""
    auto_suppress_max_severity: Severity = Severity.HIGH
    """False positives above this scanner severity become issues for a human, not suppressions."""
    suppression_ttl_days: int = Field(default=30, ge=1, le=365)
    cooldown_days: int = Field(default=90, ge=0, le=730)
    """After a secubot PR is closed unmerged (or its issue is closed), wait this long."""
    dismissed_ttl_days: int = Field(default=180, ge=1, le=730)
    """Closing a secubot issue as *not planned* (false positive, accepted risk) suppresses the
    finding this long, counted from the close date. Then it is examined again."""
    auto_close: bool = True
    """Close secubot's open issues and PRs whose finding a run no longer reports (fixed by
    Dependabot or by hand, or now excluded). Only when every scanner succeeded."""


class FixConfig(_Strict):
    max_attempts: int = Field(default=3, ge=1, le=5)
    extra_commands: list[str] = Field(default_factory=list)
    """Extra Bash commands the agent may run. Exact match, or `prefix:*` (no shell operators)."""
    allow_new_files: bool = False
    sensitive_paths: list[str] = Field(default_factory=lambda: list(DEFAULT_SENSITIVE_PATHS))
    """Auth/crypto code: may only change when the finding itself is located there."""
    protected_paths: list[str] = Field(default_factory=list)
    """Added to the built-in protected list (.github/, .claude/, .secfix.yml, ...)."""
    max_changed_files: int = Field(default=10, ge=1, le=100)
    max_changed_lines: int = Field(default=400, ge=1, le=5000)


class Models(_Strict):
    triage: str = DEFAULT_MODEL
    fix: str = DEFAULT_MODEL
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    triage_budget_usd: float = Field(default=3.0, gt=0, le=50)
    """Per agent session (analysis and challenge are two sessions)."""
    fix_budget_usd: float = Field(default=10.0, gt=0, le=100)
    triage_max_turns: int = Field(default=40, ge=1, le=200)
    fix_max_turns: int = Field(default=60, ge=1, le=300)


class Suppression(_Strict):
    id: str | None = None
    """Cluster id (branch suffix) or finding fingerprint."""
    rule: str | None = None
    """Rule id, CVE/GHSA/GO id or CWE (e.g. `G404`, `CVE-2024-1234`, `CWE-338`)."""
    path: str | None = None
    """gitignore-style pattern matched against the cluster's paths."""
    reason: str = Field(min_length=10)
    expires: dt.date
    created: dt.date | None = None
    source: Literal["config", "triage"] = "config"

    @model_validator(mode="after")
    def _needs_selector(self) -> Suppression:
        if not (self.id or self.rule or self.path):
            raise ValueError("a suppression needs at least one of: id, rule, path")
        return self

    def active(self, today: dt.date) -> bool:
        return self.expires >= today


class SecfixConfig(_Strict):
    version: Literal[1] = 1
    languages: list[Literal["go", "python"]] | None = None
    """Auto-detected from go.mod / pyproject.toml / requirements*.txt when omitted."""
    paths: Paths = Field(default_factory=Paths)
    commands: Commands = Field(default_factory=Commands)
    scanners: Scanners = Field(default_factory=Scanners)
    policy: Policy = Field(default_factory=Policy)
    fix: FixConfig = Field(default_factory=FixConfig)
    models: Models = Field(default_factory=Models)
    labels: list[str] = Field(default_factory=lambda: ["security"])
    suppressions: list[Suppression] = Field(default_factory=list)

    @field_validator("labels")
    @classmethod
    def _labels(cls, v: list[str]) -> list[str]:
        return [label.strip() for label in v if label.strip()]

    # -- helpers -------------------------------------------------------------------------

    def skip_spec(self) -> pathspec.PathSpec:
        return pathspec.PathSpec.from_lines("gitignore", self.paths.skip)

    def protected_spec(self) -> pathspec.PathSpec:
        return pathspec.PathSpec.from_lines(
            "gitignore", BUILTIN_PROTECTED_PATHS + self.fix.protected_paths
        )

    def sensitive_spec(self) -> pathspec.PathSpec:
        return pathspec.PathSpec.from_lines("gitignore", self.fix.sensitive_paths)


def load_config(repo_root: Path, config_path: str | None = None) -> SecfixConfig:
    path = repo_root / (config_path or DEFAULT_CONFIG_PATH)
    if not path.is_file():
        return SecfixConfig()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    return SecfixConfig.model_validate(data)


# -- language / project detection -----------------------------------------------------------


def iter_files(repo_root: Path, skip: pathspec.PathSpec, names: set[str]) -> list[Path]:
    """Find files by exact name or `requirements*.txt`, honouring the skip patterns."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        rel_dir = Path(dirpath).relative_to(repo_root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = sorted(
            d for d in dirnames if not skip.match_file(f"{rel_dir}{d}/") and d != ".git"
        )
        for name in sorted(filenames):
            if name in names or (
                "requirements*.txt" in names
                and name.startswith("requirements")
                and name.endswith(".txt")
            ):
                rel = f"{rel_dir}{name}"
                if not skip.match_file(rel):
                    found.append(Path(dirpath) / name)
    return found


def go_modules(repo_root: Path, cfg: SecfixConfig) -> list[Path]:
    return [p.parent for p in iter_files(repo_root, cfg.skip_spec(), {"go.mod"})]


PYTHON_MARKERS = {"pyproject.toml", "setup.py", "setup.cfg", "uv.lock", "requirements*.txt"}


def python_projects(repo_root: Path, cfg: SecfixConfig) -> list[Path]:
    return sorted({p.parent for p in iter_files(repo_root, cfg.skip_spec(), PYTHON_MARKERS)})


def detect_languages(repo_root: Path, cfg: SecfixConfig) -> list[str]:
    if cfg.languages:
        return list(cfg.languages)
    langs = []
    if go_modules(repo_root, cfg):
        langs.append("go")
    if python_projects(repo_root, cfg):
        langs.append("python")
    return langs
