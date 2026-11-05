"""Scanner invocation. The scan job and the fix job's verification loop both call this, so a
finding is always re-checked with exactly the command that raised it.

Each scanner writes `<out_dir>/<tool>.sarif` with repository-relative URIs (one SARIF run
per tool, which is what GitHub code scanning expects per upload category).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from secubot.config import SecfixConfig, detect_languages, go_modules, iter_files
from secubot.pip_audit import pip_audit_to_sarif
from secubot.sarif import merge_runs, rewrite_uris

ALL_TOOLS = ["trivy-fs", "trivy-image", "govulncheck", "gosec", "bandit", "pip-audit", "semgrep"]

# Variables that must never reach a scanner or a build/test command.
SCRUBBED_ENV_PREFIXES = ("ANTHROPIC_", "ACTIONS_", "CLAUDE_")
SCRUBBED_ENV_VARS = {"GITHUB_TOKEN", "GH_TOKEN", "SECUBOT_READ_TOKEN", "INPUT_GITHUB-TOKEN"}


def scrubbed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(SCRUBBED_ENV_PREFIXES) and k not in SCRUBBED_ENV_VARS
    }
    env.update(extra or {})
    return env


@dataclass
class ScanStatus:
    tool: str
    ok: bool
    detail: str = ""
    sarif: str | None = None


def enabled_tools(repo_root: Path, cfg: SecfixConfig) -> list[str]:
    langs = set(detect_languages(repo_root, cfg))
    s = cfg.scanners
    tools = []
    if s.trivy:
        tools.append("trivy-fs")
    if s.trivy_image.enabled and (repo_root / s.trivy_image.dockerfile).is_file():
        tools.append("trivy-image")
    if "go" in langs:
        if s.govulncheck:
            tools.append("govulncheck")
        if s.gosec:
            tools.append("gosec")
    if "python" in langs:
        if s.bandit:
            tools.append("bandit")
        if s.pip_audit:
            tools.append("pip-audit")
    if s.semgrep.enabled:
        tools.append("semgrep")
    return tools


_FROM_STAGE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*\S+\s+AS\s+(\S+)", re.IGNORECASE)


def stage_line(dockerfile: Path, target: str) -> int:
    """1-based line of the `FROM ... AS <target>` instruction, else 1. Stage names are
    case-insensitive, as in docker build."""
    try:
        lines = dockerfile.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 1
    for n, text in enumerate(lines, 1):
        m = _FROM_STAGE.match(text)
        if m and m.group(1).lower() == target.lower():
            return n
    return 1


def _run(
    cmd: list[str],
    cwd: Path,
    timeout: int = 1800,
    ok_codes=(0,),
    stdout_to: Path | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=scrubbed_env(env),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return False, f"{cmd[0]}: not installed"
    except subprocess.TimeoutExpired:
        return False, f"{cmd[0]}: timed out after {timeout}s"
    if stdout_to is not None:
        stdout_to.write_text(proc.stdout or "", encoding="utf-8")
        tail = (proc.stderr or "")[-2000:]
    else:
        tail = (proc.stderr or proc.stdout or "")[-2000:]
    return proc.returncode in ok_codes, f"exit {proc.returncode}: {tail}".strip()


def _skip_dirs(cfg: SecfixConfig) -> list[str]:
    """Literal directory prefixes from paths.skip (scanner-side optimisation only)."""
    out = []
    for pattern in cfg.paths.skip:
        p = pattern.strip().rstrip("/")
        if p and not any(ch in p for ch in "*?[!") and not p.startswith("#"):
            out.append(p)
    return out


def _unreadable(repo_root: Path, pruned: list[str]) -> tuple[list[str], list[str]]:
    """Files and directories this process can't open, relative to the repository.

    Claude Code's command sandbox masks config files (`.mcp.json`, `.claude/settings.json`,
    shell rc files, ...) when the agent runs `secubot recheck`, and trivy aborts the whole
    scan on the first one ("walk error ... permission denied"). Those paths are protected,
    so secubot never acts on findings there anyway.
    """
    files: list[str] = []
    dirs: list[str] = []
    skip = {".git", *pruned}
    for current, dirnames, filenames in os.walk(repo_root):
        here = Path(current)
        rel_dir = here.relative_to(repo_root)
        keep = []
        for name in dirnames:
            rel = (rel_dir / name).as_posix()
            if rel in skip:
                continue
            try:
                with os.scandir(here / name):
                    pass
            except OSError:
                dirs.append(rel)
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in filenames:
            try:
                os.close(os.open(here / name, os.O_RDONLY | os.O_NONBLOCK))  # FIFOs: no wait
            except OSError:
                files.append((rel_dir / name).as_posix())
    return files, dirs


def _write(doc: dict, path: Path) -> None:
    path.write_text(json.dumps(doc, indent=1), encoding="utf-8")


def _load_rewritten(path: Path, repo_root: Path, prefix: str = "") -> dict:
    return rewrite_uris(json.loads(path.read_text(encoding="utf-8")), repo_root, prefix)


def run_scanner(tool: str, repo_root: Path, out_dir: Path, cfg: SecfixConfig) -> ScanStatus:
    repo_root = repo_root.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{tool}.sarif"
    tmp = Path(tempfile.mkdtemp(prefix=f"secubot-{tool}-"))
    try:
        if tool == "trivy-fs":
            cmd = [
                "trivy",
                "fs",
                "--scanners",
                "vuln,misconfig,secret,license",
                "--format",
                "sarif",
                "--output",
                str(tmp / "out.sarif"),
                "--skip-version-check",
                "--disable-telemetry",
                "--quiet",
                "--exit-code",
                "0",
            ]
            skip_dirs = _skip_dirs(cfg)
            for d in skip_dirs:
                cmd += ["--skip-dirs", d]
            bad_files, bad_dirs = _unreadable(repo_root, skip_dirs)
            for f in bad_files:
                cmd += ["--skip-files", f]
            for d in bad_dirs:
                cmd += ["--skip-dirs", d]
            ok, detail = _run([*cmd, "."], repo_root)
            if not ok:
                return ScanStatus(tool, False, detail)
            _write(_load_rewritten(tmp / "out.sarif", repo_root), target)
        elif tool == "trivy-image":
            ic = cfg.scanners.trivy_image
            image = "secubot-scan:local"
            build = ["docker", "build", "-q", "-f", ic.dockerfile, "-t", image]
            if ic.target:
                build.append(f"--target={ic.target}")
            ok, detail = _run([*build, ic.context], repo_root, timeout=3600)
            if not ok:
                return ScanStatus(tool, False, detail)
            ok, detail = _run(
                [
                    "trivy",
                    "image",
                    "--format",
                    "sarif",
                    "--output",
                    str(tmp / "out.sarif"),
                    "--skip-version-check",
                    "--disable-telemetry",
                    "--quiet",
                    "--exit-code",
                    "0",
                    image,
                ],
                repo_root,
            )
            if not ok:
                return ScanStatus(tool, False, detail)
            doc = json.loads((tmp / "out.sarif").read_text())
            # Image findings live in image layers; anchor them on the Dockerfile (on the built
            # stage's FROM line when a target is set).
            line = stage_line(repo_root / ic.dockerfile, ic.target) if ic.target else 1
            for run in doc.get("runs", []):
                for result in run.get("results", []):
                    for loc in result.get("locations", []) or []:
                        art = loc.setdefault("physicalLocation", {}).setdefault(
                            "artifactLocation", {}
                        )
                        art["uri"] = ic.dockerfile
                        art.pop("uriBaseId", None)
                        loc["physicalLocation"]["region"] = {"startLine": line}
                run.pop("originalUriBaseIds", None)
            _write(doc, target)
        elif tool in {"govulncheck", "gosec"}:
            docs = []
            for module in go_modules(repo_root, cfg):
                rel = module.relative_to(repo_root).as_posix()
                rel = "" if rel == "." else rel
                out = tmp / f"{len(docs)}.sarif"
                if tool == "govulncheck":
                    ok, detail = _run(
                        ["govulncheck", "-format", "sarif", "./..."], module, stdout_to=out
                    )
                else:
                    cmd = ["gosec", "-fmt", "sarif", "-out", str(out), "-no-fail", "-quiet"]
                    for d in _skip_dirs(cfg):
                        cmd += ["-exclude-dir", d]
                    ok, detail = _run([*cmd, "./..."], module)
                if not ok:
                    return ScanStatus(tool, False, f"{rel or '.'}: {detail}")
                docs.append(_load_rewritten(out, module, prefix=rel))
            _write(merge_runs(docs), target)
        elif tool == "bandit":
            excludes = ",".join(
                [
                    "./.git",
                    "./.venv",
                    "./venv",
                    "./node_modules",
                    *[f"./{d}" for d in _skip_dirs(cfg)],
                ]
            )
            ok, detail = _run(
                [
                    "bandit",
                    "-r",
                    ".",
                    "-f",
                    "sarif",
                    "-o",
                    str(tmp / "out.sarif"),
                    "--exit-zero",
                    "-q",
                    "-x",
                    excludes,
                ],
                repo_root,
            )
            if not ok:
                return ScanStatus(tool, False, detail)
            _write(_load_rewritten(tmp / "out.sarif", repo_root), target)
        elif tool == "pip-audit":
            status = _pip_audit(repo_root, tmp, cfg)
            if not status.ok:
                return status
            shutil.copy(tmp / "pip-audit.sarif", target)
        elif tool == "semgrep":
            cmd = [
                "semgrep",
                "scan",
                "--sarif",
                "--output",
                str(tmp / "out.sarif"),
                "--metrics=off",
                "--disable-version-check",
                "--quiet",
            ]
            for conf in cfg.scanners.semgrep.configs:
                cmd += ["--config", conf]
            for d in _skip_dirs(cfg):
                cmd += ["--exclude", d]
            # semgrep writes settings and logs under $HOME/.semgrep: keep that out of the
            # runner's home (and working on read-only homes).
            home = tmp / "home"
            home.mkdir()
            ok, detail = _run(
                [*cmd, "."], repo_root, env={"HOME": str(home), "SEMGREP_SEND_METRICS": "off"}
            )
            if not ok:
                return ScanStatus(tool, False, detail)
            _write(_load_rewritten(tmp / "out.sarif", repo_root), target)
        else:
            return ScanStatus(tool, False, "unknown tool")
        return ScanStatus(tool, True, "ok", str(target))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _requirement_sources(repo_root: Path, cfg: SecfixConfig) -> list[Path]:
    skip = cfg.skip_spec()
    locks = iter_files(repo_root, skip, {"uv.lock"})
    lock_dirs = {p.parent for p in locks}
    reqs = [
        p for p in iter_files(repo_root, skip, {"requirements*.txt"}) if p.parent not in lock_dirs
    ]
    return locks + reqs


def _fully_pinned(path: Path) -> bool:
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            if line.startswith(("-r", "-c", "-e", "--requirement", "--constraint", "--editable")):
                return False
            continue
        if "==" not in line:
            return False
    return True


def _pip_audit(repo_root: Path, tmp: Path, cfg: SecfixConfig) -> ScanStatus:
    docs = []
    for source in _requirement_sources(repo_root, cfg):
        rel = source.relative_to(repo_root).as_posix()
        req = source
        if source.name == "uv.lock":
            req = tmp / f"req-{len(docs)}.txt"
            ok, detail = _run(
                [
                    "uv",
                    "export",
                    "--frozen",
                    "--format",
                    "requirements-txt",
                    "--no-hashes",
                    "--no-header",
                    "--no-emit-project",
                    "--output-file",
                    str(req),
                ],
                source.parent,
            )
            if not ok:
                return ScanStatus("pip-audit", False, f"{rel}: {detail}")
        out = tmp / f"audit-{len(docs)}.json"
        cmd = [
            "pip-audit",
            "-r",
            str(req),
            "-f",
            "json",
            "-o",
            str(out),
            "--progress-spinner",
            "off",
            "--cache-dir",
            str(tmp / "pip-audit-cache"),
        ]
        if _fully_pinned(req):
            # No resolution, so no package build scripts run on the runner.
            cmd += ["--no-deps", "--disable-pip"]
        # Exit 1 means "vulnerabilities found" *or* "error": the report file tells them apart.
        ok, detail = _run(cmd, source.parent, ok_codes=(0, 1))
        if not ok or not out.is_file():
            return ScanStatus("pip-audit", False, f"{rel}: {detail}")
        docs.append(
            pip_audit_to_sarif(json.loads(out.read_text()), source_path=rel, repo_root=repo_root)
        )
    _write(
        merge_runs(docs) if docs else pip_audit_to_sarif({"dependencies": []}, "", repo_root),
        tmp / "pip-audit.sarif",
    )
    return ScanStatus("pip-audit", True, "ok")


def run_scanners(
    tools: list[str], repo_root: Path, out_dir: Path, cfg: SecfixConfig
) -> list[ScanStatus]:
    return [run_scanner(t, repo_root, out_dir, cfg) for t in tools]
