"""SARIF reading and rewriting.

Every scanner writes SARIF; this module turns each SARIF result into a `Finding` with a
common schema (kind, severity, CVE/CWE ids, package, reachability). Tool-specific quirks are
handled here and nowhere else. Parsing is deliberately tolerant: SARIF from real tools is
inconsistent, and a missing field must degrade a finding, not crash the run.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from secubot.models import Finding, Kind, Reachability, Severity, Source

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b")
GO_RE = re.compile(r"\bGO-\d{4}-\d{4,}\b")
PYSEC_RE = re.compile(r"\bPYSEC-\d{4}-\d+\b")
CWE_RE = re.compile(r"\bcwe[-_ /]?(\d{1,5})\b", re.IGNORECASE)

TRIVY_FIELDS = {
    "package": re.compile(r"^Package:\s*(.+)$", re.MULTILINE),
    "installed": re.compile(r"^Installed Version:\s*(.+)$", re.MULTILINE),
    "fixed": re.compile(r"^Fixed Version:\s*(.+)$", re.MULTILINE),
    "severity": re.compile(r"^Severity:\s*([A-Z]+)$", re.MULTILINE),
}
GOVULN_PKG_RE = re.compile(r"\(([^)]+)\)")

LEVEL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}
SEVERITY_WORDS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def _text(obj: Any) -> str:
    if isinstance(obj, dict):
        return str(obj.get("text") or obj.get("markdown") or "")
    return str(obj or "")


def vuln_ids_in(text: str) -> list[str]:
    ids: set[str] = set()
    for rx in (CVE_RE, GHSA_RE, GO_RE, PYSEC_RE):
        ids.update(rx.findall(text))
    return sorted(ids)


def cwes_in(text: str) -> list[str]:
    return sorted({f"CWE-{int(n)}" for n in CWE_RE.findall(text)})


def primary_vuln_id(ids: list[str]) -> str | None:
    for prefix in ("CVE-", "GHSA-", "GO-", "PYSEC-"):
        matches = sorted(i for i in ids if i.startswith(prefix))
        if matches:
            return matches[0]
    return None


def normalise_package(name: str, ecosystem_hint: str | None = None) -> str:
    """PEP 503 normalisation for Python names; Go module paths are kept (lower-cased)."""
    name = name.strip()
    if "/" in name or ecosystem_hint == "go":
        return name.lower()
    return re.sub(r"[-_.]+", "-", name).lower()


# -- path handling ----------------------------------------------------------------------------


def _uri_to_relpath(uri: str, base_uri: str | None, repo_root: Path | None) -> str:
    """Return a POSIX path relative to the repository root when possible."""
    if base_uri and not uri.startswith("file:") and not uri.startswith("/"):
        uri = base_uri.rstrip("/") + "/" + uri
    if uri.startswith("file:"):
        uri = unquote(urlparse(uri).path)
    if uri.startswith("/") and repo_root is not None:
        try:
            return Path(uri).resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            return uri
    return uri.removeprefix("./")


def _original_bases(run: dict[str, Any]) -> dict[str, str]:
    bases = {}
    for key, value in (run.get("originalUriBaseIds") or {}).items():
        if isinstance(value, dict) and value.get("uri"):
            bases[key] = value["uri"]
    return bases


def rewrite_uris(sarif: dict[str, Any], repo_root: Path, prefix: str = "") -> dict[str, Any]:
    """Make every artifact URI repository-relative (needed for code scanning and dedup).

    `prefix` is prepended to relative URIs produced by a scanner that ran in a
    sub-directory (Go modules in a monorepo, for instance).
    """
    prefix = prefix.strip("/")

    def fix(loc: dict[str, Any], bases: dict[str, str]) -> None:
        art = (loc.get("physicalLocation") or {}).get("artifactLocation")
        if not isinstance(art, dict) or "uri" not in art:
            return
        base_id = art.get("uriBaseId")
        if base_id and base_id not in bases and base_id != "%SRCROOT%":
            return  # e.g. %GOMODCACHE%: outside the repo, leave untouched
        rel = _uri_to_relpath(art["uri"], bases.get(base_id or ""), repo_root)
        if prefix and not rel.startswith("/") and "://" not in rel:
            rel = f"{prefix}/{rel}"
        art["uri"] = rel
        art.pop("uriBaseId", None)

    for run in sarif.get("runs", []):
        bases = _original_bases(run)
        for result in run.get("results", []):
            for loc in result.get("locations", []) or []:
                fix(loc, bases)
            for flow in result.get("codeFlows", []) or []:
                for tf in flow.get("threadFlows", []) or []:
                    for tfl in tf.get("locations", []) or []:
                        if isinstance(tfl.get("location"), dict):
                            fix(tfl["location"], bases)
        run.pop("originalUriBaseIds", None)
    return sarif


def merge_runs(documents: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge several single-tool SARIF documents into one run (one upload per category)."""
    if not documents:
        return {"version": "2.1.0", "runs": []}
    merged = json.loads(json.dumps(documents[0]))
    if not merged.get("runs"):
        merged["runs"] = [{"tool": {"driver": {"name": "unknown", "rules": []}}, "results": []}]
    base = merged["runs"][0]
    base.setdefault("results", [])
    rules = base.setdefault("tool", {}).setdefault("driver", {}).setdefault("rules", [])
    seen_rules = {r.get("id") for r in rules}
    for doc in documents[1:]:
        for run in doc.get("runs", []):
            run_rules = (run.get("tool") or {}).get("driver", {}).get("rules", []) or []
            for rule in run_rules:
                if rule.get("id") not in seen_rules:
                    rules.append(rule)
                    seen_rules.add(rule.get("id"))
            for result in run.get("results", []) or []:
                result = dict(result)
                result.pop("ruleIndex", None)  # indices are per-run; ruleId stays authoritative
                base["results"].append(result)
    for result in base["results"]:
        result.pop("ruleIndex", None)
    return merged


# -- result interpretation --------------------------------------------------------------------


def _rule_for(result: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, Any]:
    idx = result.get("ruleIndex")
    if (
        isinstance(idx, int)
        and 0 <= idx < len(rules)
        and rules[idx].get("id") == result.get("ruleId")
    ):
        return rules[idx]
    rid = result.get("ruleId")
    for rule in rules:
        if rule.get("id") == rid:
            return rule
    return {}


def _rule_description(rule: dict[str, Any], message: str) -> str:
    """The advisory text of a rule: which function or configuration is affected and when.

    Dependency scanners put it in fullDescription/help, not in the result message, and
    triage needs it to judge reachability. Context only: ids are never extracted from it.
    """
    text = _text(rule.get("fullDescription"))
    if len(text) < 40:  # some tools only fill `help` (trivy repeats its metadata there)
        text = _text(rule.get("help")) or text
    text = re.sub(r"[ \t]+", " ", text).strip()
    if not text or text in message:
        return ""
    return text[:1500]


def _rule_cwes(rule: dict[str, Any]) -> list[str]:
    cwes = []
    for rel in rule.get("relationships", []) or []:
        target = rel.get("target") or {}
        comp = (target.get("toolComponent") or {}).get("name", "")
        if comp.upper() == "CWE" and str(target.get("id", "")).isdigit():
            cwes.append(f"CWE-{int(target['id'])}")
    return cwes


def _security_severity(rule: dict[str, Any], result: dict[str, Any]) -> Severity | None:
    for props in (result.get("properties") or {}, rule.get("properties") or {}):
        raw = props.get("security-severity")
        if raw is not None:
            try:
                return Severity.from_score(float(raw))
            except (TypeError, ValueError):
                pass
    return None


def _tag_severity(tags: list[str]) -> Severity | None:
    for tag in tags:
        if tag.upper() in SEVERITY_WORDS:
            return Severity.parse(tag)
    return None


def _source_line(repo_root: Path | None, path: str, line: int | None) -> str | None:
    if repo_root is None or not line:
        return None
    file = repo_root / path
    try:
        if file.is_file() and file.stat().st_size < 5_000_000:
            lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
            if 0 < line <= len(lines):
                return lines[line - 1]
    except OSError:
        return None
    return None


def _snippet(region: dict[str, Any], repo_root: Path | None, path: str) -> str | None:
    snip = (region.get("snippet") or {}).get("text")
    if snip:
        return snip.strip("\n")
    return _source_line(repo_root, path, region.get("startLine"))


def line_anchor(text: str | None) -> str:
    """Location anchor that survives line shifts: hash of the whitespace-normalised line."""
    norm = re.sub(r"\s+", " ", (text or "").strip())
    return hashlib.sha256(norm.encode()).hexdigest()[:12] if norm else ""


def _classify(tool: str, rule: dict[str, Any], tags: list[str]) -> Kind:
    lowered = {t.lower() for t in tags}
    rule_id = str(rule.get("id", ""))
    if tool.startswith("trivy"):
        if "misconfiguration" in lowered:
            return Kind.IAC
        if "secret" in lowered:
            return Kind.SECRET
        if "license" in lowered:
            return Kind.LICENSE
        return Kind.DEPENDENCY
    if tool in {"govulncheck", "pip-audit"}:
        return Kind.DEPENDENCY
    if tool == "semgrep":
        if rule_id.startswith(("generic.secrets", "secrets.")):
            return Kind.SECRET
        if rule_id.startswith(("dockerfile.", "terraform.", "yaml.kubernetes", "yaml.docker")):
            return Kind.IAC
    if tool == "gosec" and rule_id == "G101":
        return Kind.SECRET
    if tool == "bandit" and rule_id in {"B105", "B106", "B107"}:
        return Kind.SECRET
    return Kind.CODE


def _govulncheck_details(result: dict[str, Any]) -> tuple[str | None, str | None, list[str]]:
    """Return (module, version, call_path) from a govulncheck result."""
    module = version = None
    call_path: list[str] = []
    for flow in result.get("codeFlows", []) or []:
        for tf in flow.get("threadFlows", []) or []:
            frames = tf.get("locations", []) or []
            for frame in frames:
                loc = frame.get("location") or {}
                msg = _text(loc.get("message"))
                phys = loc.get("physicalLocation") or {}
                art = (phys.get("artifactLocation") or {}).get("uri", "")
                line = (phys.get("region") or {}).get("startLine")
                if msg:
                    where = f" ({art}:{line})" if art and not art.startswith("/") else ""
                    call_path.append(f"{msg}{where}")
            if frames:
                mod = str(frames[-1].get("module", ""))
                if "@" in mod:
                    module, version = mod.rsplit("@", 1)
                    version = version or None
        if call_path:
            break
    if module is None:
        m = GOVULN_PKG_RE.search(_text(result.get("message")))
        if m:
            module = m.group(1).split(",")[0].strip()
    return module, version, call_path


def go_module_for(package: str, gomod_text: str) -> str:
    """Map a Go import path to the module that provides it (longest require prefix)."""
    if package == "stdlib" or "." not in package.split("/")[0]:
        return "stdlib"
    modules = re.findall(
        r"^\s*(?:require\s+)?([\w.\-~/]+\.[\w.\-~/]+)\s+v[\w.\-+]+", gomod_text, re.MULTILINE
    )
    best = ""
    for mod in modules:
        if (package == mod or package.startswith(mod + "/")) and len(mod) > len(best):
            best = mod
    return best or package


def _fixed_versions(raw: str | None) -> str | None:
    if not raw:
        return None
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return ", ".join(parts) or None


def parse_sarif(path: Path, repo_root: Path | None = None) -> list[Finding]:
    """Parse one SARIF file into (not yet fingerprinted) findings."""
    tool = path.stem
    doc = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for run in doc.get("runs", []) or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        rules = driver.get("rules", []) or []
        bases = _original_bases(run)
        for result in run.get("results", []) or []:
            finding = _parse_result(tool, result, _rule_for(result, rules), bases, repo_root)
            if finding is not None:
                findings.append(finding)
    return findings


def _parse_result(
    tool: str,
    result: dict[str, Any],
    rule: dict[str, Any],
    bases: dict[str, str],
    repo_root: Path | None,
) -> Finding | None:
    rule_id = str(result.get("ruleId") or rule.get("id") or "unknown")
    message = _text(result.get("message"))
    props = rule.get("properties") or {}
    rprops = result.get("properties") or {}
    tags = [str(t) for t in (props.get("tags") or []) + (rprops.get("tags") or [])]
    level = str(
        result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    )

    locations = result.get("locations") or []
    phys = (locations[0].get("physicalLocation") or {}) if locations else {}
    art = phys.get("artifactLocation") or {}
    region = phys.get("region") or {}
    uri = str(art.get("uri") or "")
    if not uri:
        return None
    path = _uri_to_relpath(uri, bases.get(str(art.get("uriBaseId") or "")), repo_root)

    corpus = "\n".join(
        [
            rule_id,
            str(rule.get("name") or ""),
            _text(rule.get("shortDescription")),
            _text(rule.get("fullDescription")),
            _text(rule.get("help")),
            message,
            " ".join(tags),
        ]
    )
    # Vulnerability ids only from structured fields: advisory descriptions often mention
    # *other* CVEs ("incomplete fix for CVE-..."), which would wrongly merge advisories.
    vuln_ids = vuln_ids_in(
        "\n".join(
            [
                rule_id,
                str(rule.get("name") or ""),
                _text(rule.get("shortDescription")),
                " ".join(tags),
            ]
        )
    )
    cwes = sorted(set(cwes_in(corpus)) | set(_rule_cwes(rule)))
    kind = _classify(tool, rule, tags)

    severity = (
        _security_severity(rule, result)
        or _tag_severity(tags)
        or Severity.parse(str(rprops.get("issue_severity") or "") or None)
        or LEVEL_SEVERITY.get(level, Severity.MEDIUM)
    )
    reachable = Reachability.UNKNOWN
    package = installed = fixed = None
    call_path: list[str] = []

    if tool.startswith("trivy"):
        fields = {k: rx.search(message) for k, rx in TRIVY_FIELDS.items()}
        if fields["severity"]:
            severity = Severity.parse(fields["severity"].group(1), severity) or severity
        if kind in (Kind.DEPENDENCY, Kind.LICENSE) and fields["package"]:
            package = fields["package"].group(1).strip()
            installed = fields["installed"].group(1).strip() if fields["installed"] else None
            fixed = _fixed_versions(fields["fixed"].group(1)) if fields["fixed"] else None
    elif tool == "govulncheck":
        reachable = Reachability.YES if level == "error" else Reachability.NO
        severity = Severity.HIGH if level == "error" else Severity.LOW
        module, installed, call_path = _govulncheck_details(result)
        if module and repo_root is not None and (repo_root / path).is_file():
            module = go_module_for(module, (repo_root / path).read_text(errors="replace"))
        elif module and "." not in module.split("/")[0]:
            module = "stdlib"
        package = module
    elif tool == "pip-audit":
        package = rprops.get("package")
        installed = rprops.get("installed_version")
        fixed = _fixed_versions(", ".join(rprops.get("fixed_versions") or []))

    if package:
        package = normalise_package(package, "go" if tool == "govulncheck" else None)
        if tool.startswith("trivy") and path.endswith(("go.mod", "go.sum")):
            package = package.lower()

    first_line = message.splitlines()[0] if message else ""
    if tool in {"semgrep", "bandit"} and first_line:
        # Their rule descriptions are ids ("Semgrep Finding: ...", "blacklist"); the message
        # is the human-readable part.
        title = re.split(r"(?<=[.!?])\s", first_line, maxsplit=1)[0]
    else:
        title = _text(rule.get("shortDescription")) or str(rule.get("name") or "") or first_line
    title = re.sub(r"\s+", " ", title).strip()[:200] or rule_id

    start = region.get("startLine")
    end = region.get("endLine") or start
    if kind == Kind.DEPENDENCY or kind == Kind.LICENSE:
        snippet = None
        anchor = package or rule_id
    elif kind == Kind.SECRET:
        # Never copy secret material into artifacts or PR bodies: anchor on a hash of the
        # real line, keep only the scanner's (masked) snippet if it is masked.
        region_snip = (region.get("snippet") or {}).get("text")
        snippet = region_snip if region_snip and "***" in region_snip else None
        anchor = line_anchor(_source_line(repo_root, path, start) or region_snip or str(start))
    else:
        snippet = _snippet(region, repo_root, path)
        anchor = line_anchor(snippet) or f"L{start}"
    return Finding(
        kind=kind,
        severity=severity,
        title=title,
        path=path,
        start_line=int(start) if isinstance(start, int) else None,
        end_line=int(end) if isinstance(end, int) else None,
        snippet=snippet[:500] if snippet else None,
        anchor=anchor,
        vuln_ids=vuln_ids,
        cwes=cwes,
        package=package,
        installed_version=installed,
        fixed_version=fixed,
        reachable=reachable,
        call_path=call_path[:20],
        sources=[
            Source(
                tool=tool,
                rule_id=rule_id,
                level=level,
                # Secret findings: scanner messages can echo the credential (bandit B105 does).
                message=(title if kind == Kind.SECRET else message)[:2000],
                description="" if kind == Kind.SECRET else _rule_description(rule, message),
                help_uri=rule.get("helpUri"),
            )
        ],
    )
