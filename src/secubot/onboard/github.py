"""Everything `secubot onboard` does on GitHub.

User actions go through `gh` with the user's own login, like `secubot publish` does: one
login, and `gh secret set` does the encryption. Secret values go to `gh` on stdin, never as
arguments. The GitHub App check uses PyGithub, which signs the App JWT.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Let git authenticate through gh for clone and push, without `gh auth setup-git`.
GIT_AUTH = ["-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential"]


class OnboardError(Exception):
    """A problem the user has to fix; the message says how."""


@dataclass
class AppCheck:
    slug: str
    installed: bool
    """Installed on the repository."""
    installation_id: int | None = None
    """The App's installation on the repository's owner, if any (then the repository only
    needs adding to it)."""
    installation_url: str = ""


class GitHub:
    def __init__(self, repo: str):
        self.repo = repo

    # -- plumbing ---------------------------------------------------------------------------

    def _run(self, *args: str, stdin: str | None = None, check: bool = True):
        proc = subprocess.run(list(args), input=stdin, capture_output=True, text=True, check=False)
        if check and proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            raise OnboardError(f"`{' '.join(args[:3])} …` failed: {(detail or ['?'])[-1]}")
        return proc

    def api(self, path: str, *fields: str, method: str = "GET") -> Any:
        args = ["gh", "api", "-X", method, path]
        for f in fields:
            args += ["-F" if f.split("=", 1)[1] in ("true", "false") else "-f", f]
        out = self._run(*args).stdout
        return json.loads(out) if out.strip() else None

    def _probe(self, path: str) -> bool:
        """True when GET answers 2xx (endpoints that say yes/no with 204/404)."""
        return self._run("gh", "api", path, "--silent", check=False).returncode == 0

    # -- checks -----------------------------------------------------------------------------

    def token_scopes(self) -> set[str] | None:
        """Scopes of the gh login, or None when gh can't tell (fine-grained or env token)."""
        out = self._run("gh", "auth", "status", "--active", "--hostname", "github.com", check=False)
        m = re.search(r"Token scopes:\s*(.*)", out.stdout + out.stderr)
        if not m:
            return None
        return {s.strip(" '\"") for s in m.group(1).split(",") if s.strip(" '\"")}

    def repo_info(self) -> dict:
        try:
            return self.api(f"repos/{self.repo}")
        except OnboardError as exc:
            raise OnboardError(f"{self.repo}: not found, or no access with this gh login") from exc

    def secret_names(self) -> set[str]:
        out = self._run("gh", "secret", "list", "-R", self.repo, "--json", "name").stdout
        return {s["name"] for s in json.loads(out or "[]")}

    def branch_exists(self, branch: str) -> bool:
        return self._probe(f"repos/{self.repo}/branches/{branch}")

    def vulnerability_alerts(self) -> bool:
        return self._probe(f"repos/{self.repo}/vulnerability-alerts")

    def security_updates(self) -> bool:
        try:
            return bool(self.api(f"repos/{self.repo}/automated-security-fixes").get("enabled"))
        except OnboardError:
            return False

    def workflow_permissions(self) -> dict:
        return self.api(f"repos/{self.repo}/actions/permissions/workflow")

    # -- changes ----------------------------------------------------------------------------

    def set_secret(self, name: str, value: str) -> None:
        self._run("gh", "secret", "set", name, "-R", self.repo, stdin=value)

    def enable_vulnerability_alerts(self) -> None:
        self.api(f"repos/{self.repo}/vulnerability-alerts", method="PUT")

    def enable_security_updates(self) -> None:
        self.api(f"repos/{self.repo}/automated-security-fixes", method="PUT")

    def allow_actions_prs(self, default_permissions: str) -> None:
        # Keep the default token permissions as they are; only switch on PR creation.
        self.api(
            f"repos/{self.repo}/actions/permissions/workflow",
            f"default_workflow_permissions={default_permissions}",
            "can_approve_pull_request_reviews=true",
            method="PUT",
        )

    def clone(self, dest: Path) -> None:
        url = f"https://github.com/{self.repo}.git"
        self._run("git", *GIT_AUTH, "clone", "--quiet", "--depth", "1", url, str(dest))

    def push(self, checkout: Path, branch: str) -> None:
        self._run("git", "-C", str(checkout), *GIT_AUTH, "push", "--quiet", "origin", branch)

    def add_to_installation(self, installation_id: int, repo_id: int) -> bool:
        """Add the repository to an App installation the user owns. GitHub may refuse this
        for gh's token type; False then, and the caller falls back to the browser."""
        path = f"user/installations/{installation_id}/repositories/{repo_id}"
        return self._run("gh", "api", "-X", "PUT", path, "--silent", check=False).returncode == 0

    def create_pr(self, *, head: str, base: str, title: str, body: str) -> str:
        out = self._run(
            "gh", "pr", "create", "-R", self.repo, "--head", head, "--base", base,
            "--title", title, "--body-file", "-", stdin=body,
        )  # fmt: skip
        return out.stdout.strip().splitlines()[-1]


def check_app(app_id: str, private_key: str, repo: str) -> AppCheck:
    """Check the App ID and key belong together and whether the App is installed on `repo`."""
    try:
        from github import Auth, GithubException, GithubIntegration
        from jwt.exceptions import PyJWTError
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise OnboardError(missing_extra()) from exc

    gi = GithubIntegration(auth=Auth.AppAuth(int(app_id), private_key))
    try:
        slug = gi.get_app().slug
    except GithubException as exc:
        if exc.status == 401:
            raise OnboardError(
                "GitHub rejected the App key: the App ID and the .pem don't belong together, "
                "or the key was revoked"
            ) from exc
        if exc.status == 404:
            raise OnboardError(f"there is no GitHub App with ID {app_id}") from exc
        raise OnboardError(f"could not check the App: HTTP {exc.status}") from exc
    except (PyJWTError, ValueError) as exc:  # a key that can't sign
        raise OnboardError(f"could not use the App key: {exc}") from exc
    owner, name = repo.split("/", 1)
    try:
        gi.get_repo_installation(owner, name)
        return AppCheck(slug=slug, installed=True)
    except GithubException as exc:
        if exc.status != 404:
            raise OnboardError(f"could not check the App installation: HTTP {exc.status}") from exc
    try:  # installed on the owner, just not on this repository?
        for inst in gi.get_installations():
            if inst.account and inst.account.login.lower() == owner.lower():
                return AppCheck(slug, False, inst.id, inst.html_url)
    except GithubException as exc:
        raise OnboardError(f"could not list the App's installations: HTTP {exc.status}") from exc
    return AppCheck(slug=slug, installed=False)


def missing_extra() -> str:
    return (
        "`secubot onboard` needs the `onboard` extra. From a secubot checkout:\n"
        "  uv run --extra onboard secubot onboard OWNER/REPO"
    )
