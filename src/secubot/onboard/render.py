"""The files `secubot onboard` adds: caller workflow, `.secfix.yml`, `.github/dependabot.yml`."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import yaml

from secubot.config import DEFAULT_SKIP_PATHS, SecfixConfig
from secubot.gate import SHELL_METACHARS
from secubot.onboard.analyse import Project, RepoFacts

DEFAULT_SECUBOT_REPO = "damhau/secubot"
CALLER_PATH = ".github/workflows/secfix.yml"
SECFIX_PATH = ".secfix.yml"
DEPENDABOT_PATH = ".github/dependabot.yml"


class _Dumper(yaml.SafeDumper):
    """Indent lists under their key, like hand-written YAML."""

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def _dump(data: dict, flow: bool | None) -> str:
    return yaml.dump(data, Dumper=_Dumper, sort_keys=False, default_flow_style=flow, width=100)


# -- build/test commands ----------------------------------------------------------------------


@dataclass
class Commands:
    setup: str | None = None
    build: str | None = None
    test: str | None = None
    extra: list[str] = field(default_factory=list)
    """Single commands the agent may run on its own, when build/test chain several."""


COREPACK = "npm install -g corepack && corepack enable && "
NODE = {  # manager -> (executable, directory flag, frozen install, plain install, bootstrap)
    "npm": ("npm", "--prefix", "ci", "install", ""),
    "pnpm": ("pnpm", "--dir", "install --frozen-lockfile", "install", COREPACK),
    "yarn": ("yarn", "--cwd", "install --frozen-lockfile", "install", COREPACK),
    "yarn-berry": ("yarn", "--cwd", "install --immutable", "install", COREPACK),
    "bun": ("bun", "--cwd", "install --frozen-lockfile", "install", "npm install -g bun && "),
}


def project_commands(p: Project) -> tuple[str | None, str | None, str | None]:
    """(setup, build, test) for one project, run from the repository root."""
    if p.kind == "go":
        go = f"go -C {p.path}" if p.path else "go"
        return (
            f"{go} mod download",
            f"{go} build ./...",
            f"{go} test ./..." if p.has_tests else None,
        )
    if p.kind == "python":
        if p.manager == "uv":
            uv = f"uv --directory {p.path}" if p.path else "uv"
            return f"{uv} sync --frozen", None, f"{uv} run pytest -q" if p.has_tests else None
        if p.manager == "poetry":
            poetry = f"uvx poetry --directory {p.path}" if p.path else "uvx poetry"
            test = f"{poetry} run pytest -q" if p.has_tests else None
            return f"{poetry} install --no-interaction", None, test
        cd = f"cd {p.path} && " if p.path else ""
        source = f"-r {p.requirements}" if p.requirements else "-e ."
        setup = f"{cd}uv venv && uv pip install {source}" + (" pytest" if p.has_tests else "")
        return setup, None, f"{cd}.venv/bin/python -m pytest -q" if p.has_tests else None
    exe, dir_flag, frozen, plain, bootstrap = NODE[p.manager]
    base = f"{exe} {dir_flag} {p.path}" if p.path else exe
    setup = f"{bootstrap}{base} {frozen if p.locked else plain}"
    script = next((s for s in ("typecheck", "build") if s in p.scripts), None)
    build = f"{base} run {script}" if script else None
    test = (f"{base} run test" if exe == "bun" else f"{base} test") if p.has_tests else None
    return setup, build, test


def agent_singles(build: str | None, test: str | None) -> list[str]:
    """When build/test chain several commands, the single ones the agent may run itself.

    The agent's Bash calls can't contain `&&` (Claude Code checks each part of a chain
    separately), so a chained test command is only run by the pipeline. Listing the parts in
    `fix.extra_commands` lets the agent iterate on each one.
    """
    chained = [cmd for cmd in (build, test) if cmd and " && " in cmd]
    parts: list[str] = []
    for cmd in chained:
        chain = [c.strip() for c in cmd.split(" && ")]
        if not any(c.startswith("cd ") for c in chain):  # parts that only work after a cd
            parts += chain
    return [c for c in dict.fromkeys(parts) if c and not SHELL_METACHARS.search(c)]


def make_commands(setup: str | None, build: str | None, test: str | None) -> Commands:
    return Commands(setup=setup, build=build, test=test, extra=agent_singles(build, test))


def default_commands(facts: RepoFacts) -> Commands:
    """Commands for the top-most project of each stack, chained when there are several."""
    parts = [project_commands(p) for k in facts.kinds if (p := facts.primary(k))]

    def chain(i: int) -> str | None:
        return " && ".join(c[i] for c in parts if c[i]) or None

    return make_commands(chain(0), chain(1), chain(2))


# -- .secfix.yml ------------------------------------------------------------------------------


def render_secfix(
    cmds: Commands,
    *,
    extra_skip: list[str] | None = None,
    dependencies_all: bool = False,
    max_prs: int = 1,
) -> str:
    data: dict = {"version": 1}
    commands = {
        k: v for k, v in (("setup", cmds.setup), ("build", cmds.build), ("test", cmds.test)) if v
    }
    if commands:
        data["commands"] = commands
    if extra_skip:
        skip = list(DEFAULT_SKIP_PATHS) + [s for s in extra_skip if s not in DEFAULT_SKIP_PATHS]
        data["paths"] = {"skip": skip}
    policy: dict = {"max_prs": max_prs}
    if dependencies_all:
        policy["dependencies"] = "all"
    data["policy"] = policy
    if cmds.extra:
        data["fix"] = {"extra_commands": cmds.extra}
    SecfixConfig.model_validate(data)  # never open a PR with a config secubot rejects
    header = (
        "# secubot configuration, written by `secubot onboard`. All options:\n"
        f"# https://github.com/{DEFAULT_SECUBOT_REPO}/blob/main/docs/configuration.md\n"
        "# Fixes are verified by `commands` (and a rescan). `max_prs` starts low: raise it once\n"
        "# the first PRs look right.\n"
    )
    if dependencies_all:
        header += (
            "# No Dependabot or Renovate here, so secubot takes every dependency bump\n"
            "# (`dependencies: all`). Switch back to the default once one of them is on.\n"
        )
    return header + _dump(data, flow=False)


# -- .github/dependabot.yml -------------------------------------------------------------------

ECOSYSTEM = {
    "go": "gomod",
    "uv": "uv",
    "poetry": "pip",
    "pip": "pip",
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "yarn-berry": "npm",
    "bun": "bun",
}
GROUP = {"gomod": "go", "uv": "python", "pip": "python", "npm": "node", "bun": "node"}


def dependabot_dirs(facts: RepoFacts) -> dict[str, list[str]]:
    """Ecosystem -> directories to watch."""
    dirs: dict[str, set[str]] = {}

    def add(ecosystem: str, path: str) -> None:
        dirs.setdefault(ecosystem, set()).add("/" + path)

    for p in facts.projects:
        if p.kind in ("go", "python"):
            add(ECOSYSTEM[p.manager], p.path)
    for path, manager in facts.node_roots.items():
        add(ECOSYSTEM[manager], path)
    for path in facts.docker_dirs:
        add("docker", path)
    add("github-actions", "")  # the caller workflow added here, at least
    return {eco: sorted(paths) for eco, paths in dirs.items()}


def _entry(ecosystem: str, dirs: list[str]) -> dict:
    entry: dict = {"package-ecosystem": ecosystem}
    if len(dirs) == 1:
        entry["directory"] = dirs[0]
    else:
        entry["directories"] = dirs
    entry["schedule"] = {"interval": "weekly"}
    entry["cooldown"] = {"default-days": 7}
    name = GROUP.get(ecosystem, "actions" if ecosystem == "github-actions" else ecosystem)
    if ecosystem == "github-actions":
        version_group = {"applies-to": "version-updates", "patterns": ["*"]}
    else:
        version_group = {
            "applies-to": "version-updates",
            "update-types": ["minor", "patch"],
            "patterns": ["*"],
        }
    entry["groups"] = {
        name: version_group,
        f"{name}-security": {"applies-to": "security-updates", "patterns": ["*"]},
    }
    return entry


def render_dependabot(facts: RepoFacts) -> str:
    order = ["gomod", "uv", "pip", "npm", "bun", "docker", "github-actions"]
    dirs = dependabot_dirs(facts)
    data = {"version": 2, "updates": [_entry(eco, dirs[eco]) for eco in order if eco in dirs]}
    header = (
        "# Dependabot version updates, written by `secubot onboard`.\n"
        "# Each ecosystem gets one weekly PR with its minor and patch updates, after a 7-day\n"
        "# cooldown. Security updates skip the cooldown and are grouped into their own PR.\n"
        "# Major updates stay separate PRs; when one fixes a vulnerability, secubot takes it\n"
        "# and adapts the code. GitHub Actions updates, majors included, come as one PR.\n"
    )
    return header + _dump(data, flow=None)


# -- caller workflow --------------------------------------------------------------------------


def schedule_for(repo: str) -> str:
    """A daily cron time derived from the repository name, so repositories spread out."""
    h = int.from_bytes(hashlib.sha256(repo.lower().encode()).digest()[:4], "big")
    return f"{h % 60} {(h // 60) % 24} * * *"


def render_caller(
    *,
    repo: str,
    ref: str,
    secubot_repo: str = DEFAULT_SECUBOT_REPO,
    uses_app: bool = False,
    code_scanning: bool = True,
    go_version_file: str | None = None,
) -> str:
    with_lines = [
        "      dry-run: true # remove once a dry run looks right",
        "      egress-policy: audit # remove (back to block) once a real run looks right",
    ]
    if secubot_repo != DEFAULT_SECUBOT_REPO:
        with_lines.append(f"      secubot-repository: {secubot_repo}")
    if not code_scanning:
        with_lines.append("      code-scanning: false # private repository without Code Security")
    if go_version_file:
        with_lines.append(f"      go-version-file: {go_version_file}")
    secret_lines = ["      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}"]
    if uses_app:
        secret_lines += [
            "      SECUBOT_APP_ID: ${{ secrets.SECUBOT_APP_ID }}",
            "      SECUBOT_APP_PRIVATE_KEY: ${{ secrets.SECUBOT_APP_PRIVATE_KEY }}",
        ]
    return "\n".join(
        [
            "# secubot caller, written by `secubot onboard`. It starts as a dry run with egress",
            "# audit; then remove `dry-run`, then `egress-policy`, then enable the schedule.",
            "name: secfix",
            "on:",
            "  workflow_dispatch:",
            f'  # schedule: [{{ cron: "{schedule_for(repo)}" }}] # once a real run looks right',
            "permissions: {}",
            "concurrency: { group: secfix, cancel-in-progress: false }",
            "jobs:",
            "  secfix:",
            f"    uses: {secubot_repo}/.github/workflows/secfix.yml@{ref}",
            "    permissions: { contents: write, pull-requests: write, issues: write,"
            " security-events: write, actions: read }",
            "    with:",
            *with_lines,
            "    secrets:",
            *secret_lines,
            "",
        ]
    )


# -- pull request -----------------------------------------------------------------------------


def pr_body(
    *, repo: str, facts: RepoFacts, files: dict[str, str], cmds: Commands, secubot_repo: str
) -> str:
    detected = ", ".join(p.label for p in facts.projects) or "no Go, Python or Node project"
    lines = [
        f"Sets up [secubot](https://github.com/{secubot_repo}) on this repository "
        "(written by `secubot onboard`).",
        "",
        f"**Detected:** {detected}.",
        "",
        "**Adds:**",
    ]
    if CALLER_PATH in files:
        lines.append(
            f"- `{CALLER_PATH}`: runs secubot. It starts as a dry run (nothing is pushed or "
            "opened) with egress `audit`."
        )
    if SECFIX_PATH in files:
        verified = ", ".join(f"`{c}`" for c in (cmds.setup, cmds.build, cmds.test) if c)
        lines.append(f"- `{SECFIX_PATH}`: fixes are verified with {verified or 'a rescan only'}.")
    if DEPENDABOT_PATH in files:
        ecosystems = ", ".join(dependabot_dirs(facts))
        lines.append(
            f"- `{DEPENDABOT_PATH}`: weekly grouped minor/patch updates ({ecosystems}); "
            "majors stay separate."
        )
    lines += [
        "",
        "**After merging:**",
        "",
        f"1. Start a dry run: `gh workflow run secfix.yml -R {repo}`, and read its job summary.",
        "2. When the findings look right, remove `dry-run: true` and run it again. secubot then "
        "opens draft PRs and issues.",
        "3. Once a real run passes, remove `egress-policy: audit` and enable the `schedule:` line.",
        "",
        f"See the [onboarding guide](https://github.com/{secubot_repo}/blob/main/docs/onboarding.md).",
    ]
    return "\n".join(lines) + "\n"
