"""The `secubot onboard` flow: check, clone, analyse, ask, show the plan, then do it.

Nothing changes on GitHub before the final "Go ahead?". Then, in order:
secrets -> repository settings -> branch, commit, push and pull request.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from secubot import __version__
from secubot.onboard.analyse import RepoFacts, analyse
from secubot.onboard.github import GitHub, OnboardError, check_app, missing_extra
from secubot.onboard.render import (
    CALLER_PATH,
    DEFAULT_SECUBOT_REPO,
    DEPENDABOT_PATH,
    SECFIX_PATH,
    Commands,
    default_commands,
    dependabot_dirs,
    make_commands,
    pr_body,
    render_caller,
    render_dependabot,
    render_secfix,
)
from secubot.onboard.settings import OnboardSettings, load, run_secret_command

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PR_TITLE = "Set up secubot"
ASK_LATER = "you'll be asked for it"
DEFAULT_BRANCH = "secubot/onboarding"


# -- prompts ----------------------------------------------------------------------------------


class Prompter(Protocol):
    def text(
        self, message: str, default: str = "", validate: Callable[[str], bool | str] | None = None
    ) -> str: ...
    def confirm(self, message: str, default: bool = True) -> bool: ...
    def secret(self, message: str) -> str: ...
    def path(self, message: str) -> str: ...
    def pause(self, message: str) -> None: ...


class QuestionaryPrompter:
    def __init__(self):
        try:
            import questionary
        except ImportError as exc:
            raise OnboardError(missing_extra()) from exc
        self.q = questionary

    @staticmethod
    def _answer(value):
        if value is None:  # Ctrl-C
            raise KeyboardInterrupt
        return value

    def text(self, message, default="", validate=None):
        kwargs = {"validate": validate} if validate else {}
        return self._answer(self.q.text(message, default=default, **kwargs).ask())

    def confirm(self, message, default=True):
        return self._answer(self.q.confirm(message, default=default).ask())

    def secret(self, message):
        return self._answer(self.q.password(message).ask())

    def path(self, message):
        return self._answer(self.q.path(message).ask())

    def pause(self, message):
        self._answer(self.q.press_any_key_to_continue(message).ask())


class DefaultsPrompter:
    """`--yes`: every question takes its default; a question without one is an error."""

    def text(self, message, default="", validate=None):
        return default

    def confirm(self, message, default=True):
        return default

    def secret(self, message):
        raise OnboardError(
            f"{message}: no value with --yes (pass --api-key-file, or set api_key_command "
            "in the config file)"
        )

    def path(self, message):
        raise OnboardError(f"{message}: no value with --yes")

    def pause(self, message):
        raise OnboardError(message)


# -- the plan ---------------------------------------------------------------------------------


@dataclass
class Plan:
    repo: str
    base: str
    branch: str
    secubot_repo: str = DEFAULT_SECUBOT_REPO
    files: dict[str, str] = field(default_factory=dict)
    kept: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    commands: Commands = field(default_factory=Commands)
    api_key: str | None = None
    api_key_note: str = ""
    app: tuple[str, str] | None = None
    """(App ID, private key PEM) to store."""
    app_slug: str = ""
    install_into: int | None = None
    """App installation to add the repository to."""
    install_url: str = ""
    repo_id: int = 0
    allow_prs: bool = False
    default_permissions: str = "read"
    alerts: bool = False
    security_updates: bool = False

    def actions(self) -> list[str]:
        out = []
        if self.install_into:
            out.append(f"add {self.repo} to the {self.app_slug} App's installation")
        if self.api_key or self.api_key_note == ASK_LATER:
            out.append(f"set ANTHROPIC_API_KEY ({self.api_key_note})")
        if self.app:
            out.append(f"set SECUBOT_APP_ID and SECUBOT_APP_PRIVATE_KEY (App {self.app_slug})")
        if self.alerts:
            out.append("turn on Dependabot alerts")
        if self.security_updates:
            out.append("turn on Dependabot security updates")
        if self.allow_prs:
            out.append("allow GitHub Actions to create pull requests")
        if self.files:
            out.append(f"open a PR from `{self.branch}` adding {', '.join(self.files)}")
        return out


def _tail(key: str) -> str:
    return f"sk-ant-...{key[-4:]}"


def _check_api_key(key: str) -> str:
    key = re.sub(r"\s", "", key)
    if key.startswith("sk-ant-oat"):
        raise OnboardError(
            "that is a subscription OAuth token; secubot needs a Console API key (sk-ant-api...)"
        )
    if not re.match(r"^sk-ant-\S+$", key):
        raise OnboardError("that doesn't look like an Anthropic API key (sk-ant-...)")
    return key


def _read_key_file(path: str) -> str:
    try:
        return Path(path).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        raise OnboardError(f"cannot read {path}: {exc.strerror}") from exc


def _api_key_sources(args, conf: OnboardSettings):
    """Where the key can come from, best first: (description, reader, explicit)."""
    if args.api_key_file:
        yield args.api_key_file, lambda: _read_key_file(args.api_key_file), True
    if conf.api_key_file:
        yield conf.api_key_file, lambda: _read_key_file(conf.api_key_file), False
    if conf.api_key_command:
        cmd = conf.api_key_command
        yield f"`{cmd}`", lambda: run_secret_command(cmd, "api_key_command"), False
    if os.environ.get("ANTHROPIC_API_KEY"):
        yield "$ANTHROPIC_API_KEY", lambda: os.environ["ANTHROPIC_API_KEY"], False


def _ask_api_key(args, conf: OnboardSettings, plan: Plan, has_secret: bool, ask: Prompter):
    if args.no_api_key:
        return
    sources = list(_api_key_sources(args, conf))
    explicit = bool(sources) and sources[0][2]
    if (
        has_secret
        and not explicit  # --api-key-file means "set this one"
        and not ask.confirm(
            "ANTHROPIC_API_KEY is already set on the repository. Replace it?", False
        )
    ):
        plan.notes.append("ANTHROPIC_API_KEY is already set on the repository, kept")
        return
    key, source = None, ""
    for source, read, _ in sources:
        key = read()
        if source != "$ANTHROPIC_API_KEY":
            break
        # A generic variable: it may hold another workspace's key.
        tail = _tail(re.sub(r"\s", "", key))
        if ask.confirm(f"Use the API key from $ANTHROPIC_API_KEY ({tail})?", True):
            break
        key = None
    if not key:
        if args.dry_run:
            plan.api_key_note = ASK_LATER
            return
        key, source = ask.secret("Anthropic API key (sk-ant-api...)"), "typed in"
    plan.api_key = _check_api_key(key)
    plan.api_key_note = f"{_tail(plan.api_key)} from {source}"


def _ask_app(args, conf: OnboardSettings, plan: Plan, configured: bool, ask: Prompter) -> bool:
    """Fill plan.app when App credentials should be stored. Returns whether publish will use
    an App (one stored now or one already configured)."""
    if args.no_app:
        return configured
    explicit = bool(args.app_id or args.app_key)
    if explicit:
        app_id, key_file, key_cmd = args.app_id or "", args.app_key or "", None
    else:
        app_id = str(conf.app_id or "")
        key_file, key_cmd = conf.app_key_file or "", conf.app_key_command
    if configured and not explicit:
        if not ask.confirm(
            "A GitHub App is already configured on the repository. Replace its ID and key?",
            False,
        ):
            return True
    elif not (configured or app_id) and not ask.confirm(
        "Use a GitHub App for publish? Then your CI runs on secubot's PRs (recommended; "
        "create the App first, see docs/onboarding.md)",
        False,
    ):
        return False
    if not app_id and not explicit:
        app_id = ask.text("App ID (numeric)", validate=lambda v: v.isdigit() or "a number")
        key_file = ask.path("Path to the App's private key (.pem)")
    if not (app_id and (key_file or key_cmd)):
        raise OnboardError("give both --app-id and --app-key, or neither")
    if not app_id.isdigit():
        raise OnboardError("the App ID is a number (not the client ID)")
    if key_file:
        pem, where = _read_key_file(key_file), key_file
    else:
        pem, where = run_secret_command(key_cmd, "app_key_command"), f"`{key_cmd}`"
    if "PRIVATE KEY-----" not in pem:
        raise OnboardError(f"{where} is not a PEM private key")
    check = check_app(app_id, pem, plan.repo)
    if not check.installed and check.installation_id:  # added after "Go ahead?"
        plan.install_into, plan.install_url = check.installation_id, check.installation_url
    elif not check.installed:
        # Not on the owner at all: only the browser can create an installation.
        owner = plan.repo.split("/")[0]
        url = f"https://github.com/apps/{check.slug}/installations/new"
        if args.dry_run:
            plan.notes.append(f"the App {check.slug} is not installed on {owner}: {url}")
        while not check.installed and not args.dry_run:
            ask.pause(f"The App is not installed on {owner}. Install it at {url}, then press a key")
            check = check_app(app_id, pem, plan.repo)
    plan.app, plan.app_slug = (app_id, pem), check.slug
    return True


def _ask_commands(args, facts: RepoFacts, ask: Prompter) -> Commands:
    defaults = default_commands(facts)
    values = {}
    for name, hint in (
        ("setup", "runs once before the agent (install dependencies)"),
        ("build", "the agent's change must build"),
        ("test", "the agent's change must pass"),
    ):
        flag = getattr(args, name)
        default = flag if flag is not None else (getattr(defaults, name) or "")
        values[name] = ask.text(f"{name.capitalize()} command ({hint}; empty for none)", default)
    return make_commands(*(values[n].strip() or None for n in ("setup", "build", "test")))


def build_plan(
    args, gh: GitHub, facts: RepoFacts, info: dict, ask: Prompter, conf: OnboardSettings
) -> Plan:
    plan = Plan(
        repo=args.target,
        base=info["default_branch"],
        branch=args.branch,
        secubot_repo=args.secubot_repo,
        repo_id=info.get("id", 0),
    )
    secrets = gh.secret_names()

    # Build and test commands ------------------------------------------------------------
    skip: list[str] = []
    if facts.secfix_config:
        plan.kept.append(SECFIX_PATH)
    else:
        plan.commands = _ask_commands(args, facts, ask)
        answer = ask.text(
            "Extra paths to skip (comma-separated, e.g. docs/, examples/)", args.skip or ""
        )
        skip = [s.strip() for s in answer.split(",") if s.strip()]

    # Dependabot ------------------------------------------------------------------------
    want_dependabot_file = False
    if facts.dependabot_config:
        plan.kept.append(facts.dependabot_config)
    elif facts.renovate_config:
        plan.notes.append(f"{facts.renovate_config} found: Renovate updates dependencies")
    elif args.dependabot:
        ecosystems = ", ".join(dependabot_dirs(facts))
        want_dependabot_file = ask.confirm(
            f"Add {DEPENDABOT_PATH}? Weekly grouped minor/patch updates for {ecosystems}", True
        )
    alerts_on, updates_on = gh.vulnerability_alerts(), gh.security_updates()
    if (
        not (alerts_on and updates_on)
        and args.dependabot
        and ask.confirm(
            "Turn on Dependabot alerts and security updates?", not facts.renovate_config
        )
    ):
        plan.alerts, plan.security_updates = not alerts_on, not updates_on
    updates_on = updates_on or plan.security_updates
    # Without Dependabot or Renovate, secubot takes every bump (docs/onboarding.md).
    dependencies_all = not (
        facts.dependabot_config or facts.renovate_config or want_dependabot_file or updates_on
    )

    # Credentials and settings -----------------------------------------------------------
    uses_app = _ask_app(args, conf, plan, "SECUBOT_APP_ID" in secrets, ask)
    _ask_api_key(args, conf, plan, "ANTHROPIC_API_KEY" in secrets, ask)
    if not uses_app:
        perms = gh.workflow_permissions()
        plan.default_permissions = perms.get("default_workflow_permissions", "read")
        if not perms.get("can_approve_pull_request_reviews") and ask.confirm(
            "Allow GitHub Actions to create pull requests? Without an App, publish needs it", True
        ):
            plan.allow_prs = True

    # Files --------------------------------------------------------------------------------
    if not facts.secfix_config:
        plan.files[SECFIX_PATH] = render_secfix(
            plan.commands, extra_skip=skip, dependencies_all=dependencies_all
        )
    if facts.caller:
        plan.kept.append(facts.caller)
        caller_text = (Path(args.checkout) / facts.caller).read_text(encoding="utf-8")
        if uses_app and "SECUBOT_APP_ID" not in caller_text:
            plan.notes.append(
                f"{facts.caller} doesn't pass SECUBOT_APP_ID / SECUBOT_APP_PRIVATE_KEY: add "
                "them under `secrets:` or publish won't use the App"
            )
    else:
        go = facts.primary("go")
        private = info.get("visibility") != "public"
        plan.files[CALLER_PATH] = render_caller(
            repo=args.target,
            ref=args.ref,
            secubot_repo=args.secubot_repo,
            uses_app=uses_app,
            code_scanning=not private or _code_security_on(info),
            go_version_file=f"{go.path}/go.mod" if go and go.path else None,
        )
    if want_dependabot_file:
        plan.files[DEPENDABOT_PATH] = render_dependabot(facts)
    return plan


def _code_security_on(info: dict) -> bool:
    sa = info.get("security_and_analysis") or {}
    return any(
        (sa.get(k) or {}).get("status") == "enabled" for k in ("code_security", "advanced_security")
    )


# -- carrying it out --------------------------------------------------------------------------


def _git(checkout: Path, *args: str) -> None:
    proc = subprocess.run(
        ["git", "-C", str(checkout), *args], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise OnboardError(f"git {args[0]} failed: {(proc.stderr or proc.stdout).strip()}")


def _install_app(plan: Plan, gh: GitHub, ask: Prompter, out) -> None:
    if gh.add_to_installation(plan.install_into, plan.repo_id):
        out(f"  added {plan.repo} to the {plan.app_slug} App's installation")
        return
    while not check_app(*plan.app, plan.repo).installed:
        ask.pause(
            f"GitHub didn't let gh add {plan.repo} to the App. Add it under Repository access "
            f"at {plan.install_url}, then press a key"
        )
    out(f"  {plan.app_slug} is installed on {plan.repo}")


def execute(
    plan: Plan, gh: GitHub, checkout: Path, facts: RepoFacts, ask: Prompter, out=print
) -> str | None:
    if plan.install_into:  # first: if it can't be done, nothing else has changed yet
        _install_app(plan, gh, ask, out)
    if plan.api_key:
        gh.set_secret("ANTHROPIC_API_KEY", plan.api_key)
        out("  set ANTHROPIC_API_KEY")
    if plan.app:
        gh.set_secret("SECUBOT_APP_ID", plan.app[0])
        gh.set_secret("SECUBOT_APP_PRIVATE_KEY", plan.app[1])
        out("  set SECUBOT_APP_ID and SECUBOT_APP_PRIVATE_KEY")
    if plan.alerts:  # security updates need alerts on first
        gh.enable_vulnerability_alerts()
        out("  turned on Dependabot alerts")
    if plan.security_updates:
        gh.enable_security_updates()
        out("  turned on Dependabot security updates")
    if plan.allow_prs:
        gh.allow_actions_prs(plan.default_permissions)
        out("  allowed GitHub Actions to create pull requests")
    if not plan.files:
        return None
    _git(checkout, "switch", "--quiet", "-c", plan.branch)
    for rel, content in plan.files.items():
        path = checkout / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(checkout, "add", "--", *plan.files)
    message = "chore: set up secubot\n\nWritten by `secubot onboard`:\n" + "".join(
        f"- {f}\n" for f in plan.files
    )
    _git(checkout, "commit", "--quiet", "-m", message)
    gh.push(checkout, plan.branch)
    body = pr_body(
        repo=plan.repo,
        facts=facts,
        files=plan.files,
        cmds=plan.commands,
        secubot_repo=plan.secubot_repo,
    )
    url = gh.create_pr(head=plan.branch, base=plan.base, title=PR_TITLE, body=body)
    out(f"  opened {url}")
    return url


# -- entry point ------------------------------------------------------------------------------


def _show_facts(facts: RepoFacts, out) -> None:
    out("Found:")
    for p in facts.projects:
        tests = "tests" if p.has_tests else "no tests found"
        out(f"  - {p.label}, {tests}")
    if not facts.projects:
        out("  - no Go, Python or Node project (secubot still scans with trivy and semgrep)")
    if facts.docker_dirs:
        out(f"  - Dockerfiles in {', '.join(d or '/' for d in facts.docker_dirs)}")
    for name, value in (
        ("caller workflow", facts.caller),
        ("Dependabot config", facts.dependabot_config),
        ("Renovate config", facts.renovate_config),
        (".secfix.yml", SECFIX_PATH if facts.secfix_config else None),
    ):
        if value:
            out(f"  - existing {name}: {value} (kept as it is)")


def apply_settings(args, conf: OnboardSettings) -> None:
    """Fill what the command line left unset: from the config file, else the default."""
    args.secubot_repo = args.secubot_repo or conf.secubot_repo or DEFAULT_SECUBOT_REPO
    # the major line, like callers use
    args.ref = args.ref or conf.ref or f"v{__version__.split('.')[0]}"
    args.branch = args.branch or conf.branch or DEFAULT_BRANCH
    if args.dependabot is None:
        args.dependabot = conf.dependabot


def onboard(args, gh: GitHub, ask: Prompter, out=print, conf: OnboardSettings | None = None):
    conf = conf or OnboardSettings()
    apply_settings(args, conf)
    info = gh.repo_info()
    if not (info.get("permissions") or {}).get("admin"):
        raise OnboardError(f"you need admin on {args.target} to set secrets and settings")

    with tempfile.TemporaryDirectory(prefix="secubot-onboard-") as tmp:
        checkout = Path(tmp) / "repo"
        out(f"Cloning {args.target} ({info['default_branch']})...")
        gh.clone(checkout)
        args.checkout = str(checkout)
        facts = analyse(checkout)
        _show_facts(facts, out)

        plan = build_plan(args, gh, facts, info, ask, conf)
        if plan.files:
            scopes = gh.token_scopes()
            if CALLER_PATH in plan.files and scopes is not None and "workflow" not in scopes:
                raise OnboardError(
                    "pushing a workflow file needs the gh `workflow` scope: "
                    "gh auth refresh -s workflow"
                )
            if gh.branch_exists(plan.branch):
                raise OnboardError(
                    f"branch {plan.branch} already exists on {args.target}: merge or delete it, "
                    "or pass --branch"
                )

        for note in plan.notes:
            out(f"Note: {note}")
        actions = plan.actions()
        if not actions:
            out("Nothing to do: secubot is already set up here.")
            return 0
        out("Plan:")
        for action in actions:
            out(f"  - {action}")
        if args.dry_run:
            for rel, content in plan.files.items():
                out(f"\n--- {rel}\n{content.rstrip()}")
            out("\n(dry run: nothing was changed)")
            return 0
        if not ask.confirm("Go ahead?", True):
            out("Nothing changed.")
            return 0
        url = execute(plan, gh, checkout, facts, ask, out)

    out("\nNext:")
    if url:
        out(f"  1. Review and merge {url}")
        out(f"  2. Start a dry run: gh workflow run secfix.yml -R {args.target}")
    else:
        out(f"  Start a run: gh workflow run secfix.yml -R {args.target}")
    return 0


def run(args) -> int:
    """`secubot onboard`."""
    if not REPO_RE.match(args.target):
        print(f"error: not OWNER/REPO: {args.target}", file=sys.stderr)
        return 2
    try:
        if args.yes:
            ask: Prompter = DefaultsPrompter()
        elif not sys.stdin.isatty():
            raise OnboardError("no terminal to ask questions on: pass --yes to take the defaults")
        else:
            ask = QuestionaryPrompter()
        settings, path = load(args.config)
        if path:
            print(f"Defaults from {path}")
        return onboard(args, GitHub(args.target), ask, conf=settings.onboard)
    except OnboardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130
