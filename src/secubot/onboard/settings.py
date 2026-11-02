"""Your defaults for `secubot onboard`, from a TOML file.

The file is `--config PATH`, else `$SECUBOT_CONFIG`, else
`$XDG_CONFIG_HOME/secubot/config.toml` (`~/.config/secubot/config.toml`). A missing default
file is fine; a missing file you named is an error.

It holds no secrets, only where to get them: a file, or a command such as a password
manager's (`cred get anthropic/secubot`). A command line flag wins over the file.
"""

from __future__ import annotations

import os
import shlex
import stat
import subprocess
import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from secubot.onboard.github import OnboardError

COMMAND_TIMEOUT = 120  # seconds; a password manager may wait for a passphrase


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OnboardSettings(_Strict):
    secubot_repo: str | None = Field(None, pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    ref: str | None = None
    branch: str | None = None
    dependabot: bool = True
    api_key_file: str | None = None
    api_key_command: str | None = None
    app_id: int | None = None
    app_key_file: str | None = None
    app_key_command: str | None = None

    @model_validator(mode="after")
    def _one_source_each(self):
        for what in ("api_key", "app_key"):
            if getattr(self, f"{what}_file") and getattr(self, f"{what}_command"):
                raise ValueError(f"set {what}_file or {what}_command, not both")
        if bool(self.app_id) != bool(self.app_key_file or self.app_key_command):
            raise ValueError("app_id and app_key_file (or app_key_command) go together")
        return self

    @property
    def commands(self) -> list[str]:
        return [c for c in (self.api_key_command, self.app_key_command) if c]


class Settings(_Strict):
    onboard: OnboardSettings = OnboardSettings()


def config_path(explicit: str | None = None) -> tuple[Path, bool]:
    """The config file to read, and whether it must exist."""
    if explicit:
        return Path(explicit).expanduser(), True
    if os.environ.get("SECUBOT_CONFIG"):
        return Path(os.environ["SECUBOT_CONFIG"]).expanduser(), True
    base = Path(os.environ.get("XDG_CONFIG_HOME") or "~/.config").expanduser()
    return base / "secubot" / "config.toml", False


def load(explicit: str | None = None) -> tuple[Settings, Path | None]:
    path, required = config_path(explicit)
    if not path.is_file():
        if required:
            raise OnboardError(f"config file not found: {path}")
        return Settings(), None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise OnboardError(f"{path}: {exc}") from exc
    try:
        settings = Settings.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'file'}: {e['msg']}" for e in exc.errors()
        )
        raise OnboardError(f"{path}: {problems}") from exc
    # A `*_command` runs as you: like ~/.ssh/config, refuse a file others can change.
    if settings.onboard.commands and path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise OnboardError(f"{path} is writable by others and runs commands: chmod go-w {path}")
    return settings, path


def run_secret_command(command: str, name: str) -> str:
    """Run a configured `*_command` (no shell) and return what it prints.

    Its stdout is never shown, even on failure: it may be the secret. Its stderr goes to
    the terminal, so the tool's own error messages and prompts reach you.
    """
    argv = shlex.split(command)
    if not argv:
        raise OnboardError(f"{name}: empty command")
    try:
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, text=True, timeout=COMMAND_TIMEOUT, check=False
        )
    except FileNotFoundError as exc:
        raise OnboardError(f"{name}: {argv[0]} not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise OnboardError(f"{name}: `{command}` did not finish in {COMMAND_TIMEOUT}s") from exc
    if proc.returncode != 0:
        raise OnboardError(f"{name}: `{command}` failed (exit {proc.returncode})")
    if not proc.stdout.strip():
        raise OnboardError(f"{name}: `{command}` printed nothing")
    return proc.stdout
