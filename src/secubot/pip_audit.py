"""pip-audit has no SARIF output; convert its JSON so it gets the same lifecycle as the rest
(code scanning upload, normalisation, re-scan during verification)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from secubot import __version__


def _line_of(package: str, source: Path | None) -> int:
    if source is None or not source.is_file():
        return 1
    name = "[-_.]+".join(re.escape(part) for part in re.split(r"[-_.]+", package.lower()))
    rx = re.compile(rf'^\s*(?:name\s*=\s*")?{name}(?:\s*[=<>!~\[;"]|$)', re.IGNORECASE)
    for i, line in enumerate(source.read_text(errors="replace").splitlines(), start=1):
        if rx.search(line):
            return i
    return 1


def pip_audit_to_sarif(
    report: dict[str, Any], source_path: str, repo_root: Path | None = None
) -> dict[str, Any]:
    source = (repo_root / source_path) if (repo_root and source_path) else None
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for dep in report.get("dependencies", []) or []:
        name = dep.get("name", "")
        version = dep.get("version", "")
        seen: set[str] = set()
        for vuln in dep.get("vulns", []) or []:
            vid = vuln.get("id", "")
            if not vid or vid in seen:
                continue  # pip-audit repeats an advisory once per alias source
            seen.add(vid)
            aliases = sorted(set(vuln.get("aliases") or []))
            fixes = vuln.get("fix_versions") or []
            description = (vuln.get("description") or "").strip()
            rules.setdefault(
                vid,
                {
                    "id": vid,
                    "name": "PythonPackageVulnerability",
                    "shortDescription": {"text": f"{vid} in {name}"},
                    "fullDescription": {"text": description[:1000] or vid},
                    "help": {"text": description[:4000] or vid},
                    "helpUri": f"https://osv.dev/vulnerability/{vid}",
                    "properties": {"tags": ["vulnerability", "security", *aliases]},
                },
            )
            results.append(
                {
                    "ruleId": vid,
                    "level": "warning",
                    "message": {
                        "text": f"Package: {name}\nInstalled Version: {version}\n"
                        f"Vulnerability {vid} ({', '.join(aliases) or 'no aliases'})\n"
                        f"Fixed Version: {', '.join(fixes) or 'none'}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": source_path or "requirements.txt"},
                                "region": {"startLine": _line_of(name, source)},
                            }
                        }
                    ],
                    "properties": {
                        "package": name,
                        "installed_version": version,
                        "fixed_versions": fixes,
                        "tags": aliases,
                    },
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "informationUri": "https://github.com/pypa/pip-audit",
                        "version": f"secubot-{__version__}",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
