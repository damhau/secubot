from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from secubot.cli import build_parser
from secubot.config import SecfixConfig, detect_languages, node_package_manager, node_version_file
from secubot.fix import agent_commands
from secubot.models import Kind
from secubot.onboard import wizard
from secubot.onboard.analyse import analyse
from secubot.onboard.github import AppCheck, OnboardError
from secubot.onboard.render import (
    CALLER_PATH,
    DEPENDABOT_PATH,
    SECFIX_PATH,
    agent_singles,
    default_commands,
    dependabot_dirs,
    render_caller,
    render_dependabot,
    render_secfix,
    schedule_for,
)
from secubot.onboard.settings import OnboardSettings, load, run_secret_command
from secubot.onboard.wizard import DefaultsPrompter, onboard


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


PNPM_WEB = {
    "web/package.json": json.dumps(
        {
            "scripts": {"test": "vitest run", "typecheck": "tsc --noEmit"},
            "devDependencies": {"typescript": "^5"},
        }
    ),
    "web/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "web/packages/ui/package.json": "{}",  # a workspace package: covered by web's lock file
}
MULTI = {
    "pyproject.toml": "[project]\nname = 'x'\n",
    "uv.lock": "",
    "tests/test_x.py": "",
    **PNPM_WEB,
    "svc/go.mod": "module example.com/svc\n",
    "svc/main_test.go": "package main\n",
    "svc/Dockerfile": "FROM scratch\n",
}


CALLER_LINE = "uses: damhau/secubot/.github/workflows/secfix.yml@v1\n"


# -- detection ------------------------------------------------------------------------------


def test_analyse_multi_stack(tmp_path):
    facts = analyse(write(tmp_path, MULTI))
    by_kind = {(p.kind, p.path): p for p in facts.projects}
    assert by_kind[("python", "")].manager == "uv" and by_kind[("python", "")].has_tests
    assert by_kind[("go", "svc")].has_tests
    web = by_kind[("node", "web")]
    assert web.manager == "pnpm" and web.typescript and web.has_tests and web.locked
    assert by_kind[("node", "web/packages/ui")].locked  # through the workspace lock file
    assert facts.node_roots == {"web": "pnpm"}
    assert facts.docker_dirs == ["svc"]
    assert facts.primary("node").path == "web"
    assert facts.kinds == ["go", "python", "node"]
    assert not (facts.caller or facts.secfix_config or facts.dependabot_config)


def test_analyse_finds_existing_setup(tmp_path):
    write(
        tmp_path,
        {
            ".github/workflows/sec.yml": CALLER_LINE,
            ".secfix.yml": "version: 1\n",
            "renovate.json": "{}",
        },
    )
    facts = analyse(tmp_path)
    assert facts.caller == ".github/workflows/sec.yml"
    assert facts.secfix_config and facts.renovate_config == "renovate.json"


def test_node_detection_in_pipeline(tmp_path):
    write(tmp_path, {**PNPM_WEB, "web/.nvmrc": "22\n"})
    assert detect_languages(tmp_path, SecfixConfig()) == ["node"]
    assert node_version_file(tmp_path, SecfixConfig()) == "web/.nvmrc"


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ({"package.json": "{}", "package-lock.json": "{}"}, "npm"),
        ({"package.json": "{}", "yarn.lock": ""}, "yarn"),
        ({"package.json": "{}", "yarn.lock": "", ".yarnrc.yml": ""}, "yarn-berry"),
        ({"package.json": '{"packageManager": "pnpm@9.1.0"}'}, "pnpm"),
        ({"package.json": '{"packageManager": "yarn@1.22.0"}'}, "yarn"),
        ({"package.json": "{}"}, "npm"),
    ],
)
def test_node_package_manager(tmp_path, files, expected):
    write(tmp_path, files)
    assert node_package_manager(tmp_path, tmp_path) == expected


def test_node_dependency_upgrade_commands(tmp_path):
    write(tmp_path, PNPM_WEB)
    cluster = SimpleNamespace(kind=Kind.DEPENDENCY, path="web/pnpm-lock.yaml")
    cmds = agent_commands(cluster, SecfixConfig(), tmp_path)
    assert "pnpm add:*" in cmds and "pnpm update:*" in cmds


def test_npm_config_is_protected():
    spec = SecfixConfig().protected_spec()
    assert spec.match_file(".npmrc") and spec.match_file("web/.npmrc")
    assert spec.match_file(".yarn/releases/yarn-4.cjs") and spec.match_file(".pnpmfile.cjs")


# -- rendering ------------------------------------------------------------------------------


def test_default_commands_chain_stacks(tmp_path):
    cmds = default_commands(analyse(write(tmp_path, MULTI)))
    assert cmds.setup == (
        "go -C svc mod download && uv sync --frozen && "
        "npm install -g corepack && corepack enable && pnpm --dir web install --frozen-lockfile"
    )
    assert cmds.build == "go -C svc build ./... && pnpm --dir web run typecheck"
    assert cmds.test == "go -C svc test ./... && uv run pytest -q && pnpm --dir web test"
    # the agent can't run a chain, so it gets each part
    assert "uv run pytest -q" in cmds.extra and "pnpm --dir web test" in cmds.extra


def test_default_commands_single_stack_and_pip_subdir(tmp_path):
    write(tmp_path, {"api/requirements.txt": "flask==3.0\n", "api/test_app.py": ""})
    cmds = default_commands(analyse(tmp_path))
    assert cmds.setup == "cd api && uv venv && uv pip install -r requirements.txt pytest"
    assert cmds.test == "cd api && .venv/bin/python -m pytest -q"
    assert cmds.extra == []  # parts after a `cd` only work in that directory
    assert agent_singles("go build ./...", "go test ./...") == []


def test_render_secfix_is_valid_config(tmp_path):
    cmds = default_commands(analyse(write(tmp_path, MULTI)))
    text = render_secfix(cmds, extra_skip=["docs/"], dependencies_all=True)
    cfg = SecfixConfig.model_validate(yaml.safe_load(text))
    assert cfg.commands.test == cmds.test and cfg.fix.extra_commands == cmds.extra
    assert "docs/" in cfg.paths.skip and "node_modules/" in cfg.paths.skip  # defaults kept
    assert cfg.policy.dependencies == "all" and cfg.policy.max_prs == 1


def test_render_dependabot(tmp_path):
    write(tmp_path, {**MULTI, "Dockerfile": "FROM scratch\n"})
    facts = analyse(tmp_path)
    data = yaml.safe_load(render_dependabot(facts))
    entries = {u["package-ecosystem"]: u for u in data["updates"]}
    assert list(entries) == ["gomod", "uv", "npm", "docker", "github-actions"]
    assert entries["npm"]["directory"] == "/web"  # not /web/packages/ui
    assert entries["docker"]["directories"] == ["/", "/svc"]
    groups = entries["uv"]["groups"]
    assert groups["python"]["update-types"] == ["minor", "patch"]
    assert groups["python-security"]["applies-to"] == "security-updates"
    assert "update-types" not in entries["github-actions"]["groups"]["actions"]  # majors too
    assert all(u["cooldown"] == {"default-days": 7} for u in data["updates"])
    assert dependabot_dirs(facts)["gomod"] == ["/svc"]


def test_render_caller():
    data = yaml.safe_load(
        render_caller(
            repo="o/r",
            ref="v1",
            uses_app=True,
            code_scanning=False,
            go_version_file="svc/go.mod",
            secubot_repo="me/secubot",
        )
    )
    job = data["jobs"]["secfix"]
    assert job["uses"] == "me/secubot/.github/workflows/secfix.yml@v1"
    assert job["with"] == {
        "dry-run": True,
        "egress-policy": "audit",
        "secubot-repository": "me/secubot",
        "code-scanning": False,
        "go-version-file": "svc/go.mod",
    }
    assert set(job["secrets"]) == {
        "ANTHROPIC_API_KEY",
        "SECUBOT_APP_ID",
        "SECUBOT_APP_PRIVATE_KEY",
    }
    plain = yaml.safe_load(render_caller(repo="o/r", ref="v1"))["jobs"]["secfix"]
    assert set(plain["secrets"]) == {"ANTHROPIC_API_KEY"} and "code-scanning" not in plain["with"]
    assert schedule_for("o/r") == schedule_for("O/R") != schedule_for("o/other")


# -- the wizard, against a fake GitHub ------------------------------------------------------


class FakeGitHub:
    def __init__(
        self, source: Path, *, secrets=(), alerts=False, updates=False, can_pr=False, on_add=None
    ):
        self.source = source
        self.on_add = on_add  # add_to_installation: None refuses, else called
        self.secrets = dict.fromkeys(secrets, "old")
        self.alerts, self.updates, self.can_pr = alerts, updates, can_pr
        self.calls: list[str] = []
        self.pushed: dict[str, str] = {}
        self.prs: list[dict] = []

    def repo_info(self):
        return {
            "id": 99,
            "default_branch": "main",
            "visibility": "public",
            "permissions": {"admin": True},
        }

    def token_scopes(self):
        return {"repo", "workflow"}

    def clone(self, dest: Path):
        shutil.copytree(self.source, dest)
        subprocess.run(["git", "init", "-q", "-b", "main", str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(dest), "commit", "-qm", "init"], check=True)

    def secret_names(self):
        return set(self.secrets)

    def set_secret(self, name, value):
        self.secrets[name] = value

    def branch_exists(self, branch):
        return False

    def vulnerability_alerts(self):
        return self.alerts

    def security_updates(self):
        return self.updates

    def workflow_permissions(self):
        return {
            "default_workflow_permissions": "write",
            "can_approve_pull_request_reviews": self.can_pr,
        }

    def add_to_installation(self, installation_id, repo_id):
        self.calls.append(f"install:{installation_id}:{repo_id}")
        if self.on_add:
            self.on_add()
        return self.on_add is not None

    def enable_vulnerability_alerts(self):
        self.calls.append("alerts")

    def enable_security_updates(self):
        self.calls.append("security-updates")

    def allow_actions_prs(self, default_permissions):
        self.calls.append(f"allow-prs:{default_permissions}")

    def push(self, checkout: Path, branch: str):
        out = subprocess.run(
            ["git", "-C", str(checkout), "show", "--name-only", "--format=", branch],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        self.pushed = {f: (checkout / f).read_text() for f in out}

    def create_pr(self, *, head, base, title, body):
        self.prs.append({"head": head, "base": base, "title": title, "body": body})
        return "https://github.com/o/r/pull/1"


@pytest.fixture(autouse=True)
def _git_identity(monkeypatch, tmp_path):
    cfg = tmp_path / "gitconfig"
    cfg.write_text("[user]\n\tname = t\n\temail = t@example.com\n[commit]\n\tgpgsign = false\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))  # never the real config
    for var in ("ANTHROPIC_API_KEY", "SECUBOT_CONFIG"):
        monkeypatch.delenv(var, raising=False)


def args_for(*extra: str):
    return build_parser().parse_args(["onboard", "o/r", "--yes", *extra])


def key_file(tmp_path, value="sk-ant-api03-" + "x" * 30) -> str:
    path = tmp_path / "key"
    path.write_text(value + "\n")
    return str(path)


def test_wizard_sets_everything_up(tmp_path):
    src = write(tmp_path / "src", MULTI)
    gh = FakeGitHub(src)
    lines: list[str] = []
    args = args_for("--api-key-file", key_file(tmp_path), "--ref", "v1")
    assert onboard(args, gh, DefaultsPrompter(), out=lines.append) == 0

    assert gh.secrets == {"ANTHROPIC_API_KEY": "sk-ant-api03-" + "x" * 30}
    assert gh.calls == ["alerts", "security-updates", "allow-prs:write"]
    assert set(gh.pushed) == {CALLER_PATH, SECFIX_PATH, DEPENDABOT_PATH}
    cfg = SecfixConfig.model_validate(yaml.safe_load(gh.pushed[SECFIX_PATH]))
    assert cfg.policy.dependencies == "breaking-only"  # Dependabot is on
    assert gh.prs[0]["head"] == "secubot/onboarding" and gh.prs[0]["base"] == "main"
    assert "gh workflow run secfix.yml -R o/r" in gh.prs[0]["body"]
    assert any("pull/1" in line for line in lines)


def test_wizard_dry_run_changes_nothing(tmp_path):
    gh = FakeGitHub(write(tmp_path / "src", MULTI))
    lines: list[str] = []
    args = args_for("--dry-run", "--api-key-file", key_file(tmp_path), "--ref", "v1")
    assert onboard(args, gh, DefaultsPrompter(), out=lines.append) == 0
    assert gh.secrets == {} and gh.calls == [] and gh.prs == []
    assert any(line.startswith(f"\n--- {CALLER_PATH}") for line in lines)


def test_wizard_keeps_existing_setup(tmp_path):
    src = write(
        tmp_path / "src",
        {
            **MULTI,
            ".github/workflows/secfix.yml": CALLER_LINE,
            ".secfix.yml": "version: 1\n",
            ".github/dependabot.yml": "version: 2\nupdates: []\n",
        },
    )
    gh = FakeGitHub(src, secrets={"ANTHROPIC_API_KEY"}, alerts=True, updates=True, can_pr=True)
    lines: list[str] = []
    assert onboard(args_for("--ref", "v1"), gh, DefaultsPrompter(), out=lines.append) == 0
    assert gh.secrets == {"ANTHROPIC_API_KEY": "old"} and gh.prs == []
    assert "Nothing to do: secubot is already set up here." in lines


def test_wizard_without_dependabot_lets_secubot_bump(tmp_path):
    gh = FakeGitHub(write(tmp_path / "src", MULTI))
    args = args_for("--no-dependabot", "--api-key-file", key_file(tmp_path), "--ref", "v1")
    assert onboard(args, gh, DefaultsPrompter(), out=lambda _: None) == 0
    assert DEPENDABOT_PATH not in gh.pushed and "alerts" not in gh.calls
    assert yaml.safe_load(gh.pushed[SECFIX_PATH])["policy"]["dependencies"] == "all"


def test_wizard_command_flags_override_detection(tmp_path):
    gh = FakeGitHub(write(tmp_path / "src", MULTI))
    args = args_for("--api-key-file", key_file(tmp_path), "--test", "make test", "--build", "")
    assert onboard(args, gh, DefaultsPrompter(), out=lambda _: None) == 0
    commands = yaml.safe_load(gh.pushed[SECFIX_PATH])["commands"]
    assert commands["test"] == "make test" and "build" not in commands
    caller = yaml.safe_load(gh.pushed[CALLER_PATH])  # no --ref: the current major
    assert caller["jobs"]["secfix"]["uses"].endswith("/.github/workflows/secfix.yml@v1")


@pytest.mark.parametrize(
    ("value", "message"),
    [("sk-ant-oat01-" + "x" * 30, "OAuth token"), ("hello", "doesn't look like")],
)
def test_wizard_rejects_bad_api_keys(tmp_path, value, message):
    gh = FakeGitHub(write(tmp_path / "src", MULTI))
    with pytest.raises(OnboardError, match=message):
        onboard(args_for("--api-key-file", key_file(tmp_path, value)), gh, DefaultsPrompter())
    assert gh.secrets == {}


def test_wizard_yes_needs_an_api_key(tmp_path):
    gh = FakeGitHub(write(tmp_path / "src", MULTI))
    with pytest.raises(OnboardError, match="no value with --yes"):
        onboard(args_for(), gh, DefaultsPrompter(), out=lambda _: None)
    assert gh.prs == []


# -- the config file ------------------------------------------------------------------------

KEY = "sk-ant-api03-" + "k" * 30
PEM = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n"


def config(tmp_path, text: str, mode: int = 0o600) -> Path:
    path = tmp_path / "xdg" / "secubot" / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


def test_load_default_location(tmp_path):
    assert load() == (load()[0], None)  # no file: built-in defaults
    path = config(tmp_path, '[onboard]\nsecubot_repo = "me/secubot"\napi_key_command = "true"\n')
    settings, found = load()
    assert found == path and settings.onboard.secubot_repo == "me/secubot"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[onboard]\napi_key = 'sk-ant-api03-x'\n", "api_key: Extra inputs"),  # no secrets
        ("[onbaord]\n", "onbaord: Extra inputs"),
        ("[onboard]\napi_key_file = 'a'\napi_key_command = 'b'\n", "not both"),
        ("[onboard]\napp_id = 1\n", "go together"),
        ("[onboard]\nsecubot_repo = 'nope'\n", "secubot_repo"),
        ("[onboard\n", "config.toml"),
    ],
)
def test_load_rejects_bad_config(tmp_path, text, message):
    config(tmp_path, text)
    with pytest.raises(OnboardError, match=message):
        load()


def test_load_explicit_and_permissions(tmp_path, monkeypatch):
    with pytest.raises(OnboardError, match="not found"):
        load(str(tmp_path / "missing.toml"))
    monkeypatch.setenv("SECUBOT_CONFIG", str(tmp_path / "missing.toml"))
    with pytest.raises(OnboardError, match="not found"):
        load()
    path = config(tmp_path, "[onboard]\napi_key_command = 'cred get x'\n", mode=0o620)
    with pytest.raises(OnboardError, match="chmod go-w"):
        load(str(path))
    path.write_text("[onboard]\nref = 'v1'\n")  # nothing to run: fine
    assert load(str(path))[0].onboard.ref == "v1"


def test_run_secret_command(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text(KEY)
    assert run_secret_command(f"cat {secret}", "api_key_command") == KEY
    with pytest.raises(OnboardError) as exc:
        run_secret_command(f"sh -c 'cat {secret}; exit 3'", "api_key_command")
    assert "exit 3" in str(exc.value) and KEY not in str(exc.value)  # stdout never shown
    with pytest.raises(OnboardError, match="not found"):
        run_secret_command("no-such-tool-xyz get x", "api_key_command")
    with pytest.raises(OnboardError, match="printed nothing"):
        run_secret_command("true", "api_key_command")


def test_wizard_takes_defaults_from_config(tmp_path):
    gh = FakeGitHub(write(tmp_path / "src", MULTI))
    conf = OnboardSettings(
        secubot_repo="me/secubot",
        ref="v2",
        branch="chore/secubot",
        dependabot=False,
        api_key_command=f"printf %s {KEY}",
    )
    assert onboard(args_for(), gh, DefaultsPrompter(), out=lambda _: None, conf=conf) == 0
    assert gh.secrets == {"ANTHROPIC_API_KEY": KEY}
    assert gh.prs[0]["head"] == "chore/secubot" and DEPENDABOT_PATH not in gh.pushed
    job = yaml.safe_load(gh.pushed[CALLER_PATH])["jobs"]["secfix"]
    assert job["uses"] == "me/secubot/.github/workflows/secfix.yml@v2"


def test_wizard_flags_beat_config(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-" + "e" * 30)  # loses to the config
    gh = FakeGitHub(write(tmp_path / "src", MULTI))
    conf = OnboardSettings(branch="chore/secubot", dependabot=False, api_key_command="false")
    args = args_for("--branch", "x/y", "--dependabot", "--api-key-file", key_file(tmp_path))
    assert onboard(args, gh, DefaultsPrompter(), out=lambda _: None, conf=conf) == 0
    assert gh.secrets["ANTHROPIC_API_KEY"] == "sk-ant-api03-" + "x" * 30  # the flag's file
    assert gh.prs[0]["head"] == "x/y" and DEPENDABOT_PATH in gh.pushed


def test_wizard_config_key_does_not_replace_silently(tmp_path):
    gh = FakeGitHub(write(tmp_path / "src", MULTI), secrets={"ANTHROPIC_API_KEY"})
    conf = OnboardSettings(api_key_command="false")  # would fail if it ran
    assert onboard(args_for(), gh, DefaultsPrompter(), out=lambda _: None, conf=conf) == 0
    assert gh.secrets == {"ANTHROPIC_API_KEY": "old"}


def test_wizard_app_from_config(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(
        wizard, "check_app", lambda app_id, pem, repo: seen.append(pem) or AppCheck("bot", True)
    )
    pem_file = tmp_path / "app.pem"
    pem_file.write_text(PEM)
    gh = FakeGitHub(write(tmp_path / "src", MULTI))
    conf = OnboardSettings(
        app_id=42, app_key_command=f"cat {pem_file}", api_key_command=f"printf %s {KEY}"
    )
    assert onboard(args_for(), gh, DefaultsPrompter(), out=lambda _: None, conf=conf) == 0
    assert gh.secrets["SECUBOT_APP_ID"] == "42" and gh.secrets["SECUBOT_APP_PRIVATE_KEY"] == PEM
    assert seen == [PEM] and not any(c.startswith("allow-prs") for c in gh.calls)
    assert "SECUBOT_APP_ID" in yaml.safe_load(gh.pushed[CALLER_PATH])["jobs"]["secfix"]["secrets"]

    gh = FakeGitHub(write(tmp_path / "src2", MULTI), secrets={"SECUBOT_APP_ID"})
    assert (
        onboard(args_for("--no-api-key"), gh, DefaultsPrompter(), out=lambda _: None, conf=conf)
        == 0
    )
    assert gh.secrets == {"SECUBOT_APP_ID": "old"}  # already configured: kept under --yes

    gh = FakeGitHub(write(tmp_path / "src3", MULTI))
    args = args_for("--no-app", "--no-api-key")
    assert onboard(args, gh, DefaultsPrompter(), out=lambda _: None, conf=conf) == 0
    assert gh.secrets == {} and "allow-prs:write" in gh.calls


class FakeApp:
    """check_app for an App installed on the owner but not (yet) on the repository."""

    URL = "https://github.com/settings/installations/7"

    def __init__(self):
        self.installed = False

    def __call__(self, app_id, pem, repo):
        return AppCheck("bot", self.installed, None if self.installed else 7, self.URL)


@pytest.fixture
def app_conf(tmp_path, monkeypatch):
    app = FakeApp()
    monkeypatch.setattr(wizard, "check_app", app)
    pem_file = tmp_path / "app.pem"
    pem_file.write_text(PEM)
    conf = OnboardSettings(
        app_id=42, app_key_file=str(pem_file), api_key_command=f"printf %s {KEY}"
    )
    return app, conf


def test_wizard_adds_repo_to_app_installation(tmp_path, app_conf):
    app, conf = app_conf
    gh = FakeGitHub(write(tmp_path / "src", MULTI), on_add=lambda: setattr(app, "installed", True))
    lines: list[str] = []
    assert onboard(args_for(), gh, DefaultsPrompter(), out=lines.append, conf=conf) == 0
    assert gh.calls[0] == "install:7:99"  # before anything else changes
    assert gh.secrets["SECUBOT_APP_ID"] == "42"
    assert "  - add o/r to the bot App's installation" in lines


def test_wizard_app_install_falls_back_to_browser(tmp_path, app_conf):
    app, conf = app_conf

    class Clicks(DefaultsPrompter):
        def pause(self, message):
            assert FakeApp.URL in message
            app.installed = True  # the user ticked the repository

    gh = FakeGitHub(write(tmp_path / "src", MULTI))  # GitHub refuses gh's token
    assert onboard(args_for(), gh, Clicks(), out=lambda _: None, conf=conf) == 0
    assert gh.secrets["SECUBOT_APP_ID"] == "42"

    gh = FakeGitHub(write(tmp_path / "src2", MULTI))
    app.installed = False
    with pytest.raises(OnboardError, match="settings/installations/7"):  # --yes can't click
        onboard(args_for(), gh, DefaultsPrompter(), out=lambda _: None, conf=conf)
    assert gh.secrets == {} and gh.calls == ["install:7:99"]  # nothing else changed


def test_wizard_dry_run_plans_app_install(tmp_path, app_conf):
    _, conf = app_conf
    gh = FakeGitHub(write(tmp_path / "src", MULTI), on_add=lambda: None)
    lines: list[str] = []
    assert onboard(args_for("--dry-run"), gh, DefaultsPrompter(), out=lines.append, conf=conf) == 0
    assert "  - add o/r to the bot App's installation" in lines and gh.calls == []
