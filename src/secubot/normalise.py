"""Normalise and deduplicate: plain code, no LLM.

1. Every SARIF result becomes a `Finding` (see sarif.py).
2. Findings get a fingerprint = hash(kind, CVE-or-CWE, path, location anchor). Several tools
   flagging the same sink under different rule ids collapse into one finding.
3. Findings are grouped into clusters — the unit of work that gets one branch
   (`secfix/<cluster id>`), one triage and at most one PR:
     dependency -> (manifest directory, package)   one upgrade fixes all its CVEs
     code       -> (file, line anchor)             all rules firing on the same line
     iac        -> (file, rule or CVE)
     secret     -> (file, line anchor)
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath

from packaging.version import InvalidVersion, Version

from secubot.config import SecfixConfig
from secubot.models import (
    FINGERPRINT_SCHEME,
    Cluster,
    Finding,
    Kind,
    ScanReport,
    Severity,
    max_severity,
    merge_reachability,
)
from secubot.sarif import parse_sarif, primary_vuln_id


def _h(*parts: str, n: int = 16) -> str:
    return hashlib.sha256("|".join((FINGERPRINT_SCHEME, *parts)).encode()).hexdigest()[:n]


def vuln_key(f: Finding) -> str:
    if f.kind in (Kind.DEPENDENCY, Kind.LICENSE):
        return primary_vuln_id(f.vuln_ids) or f.rule_ids[0]
    if f.cwes:
        return f.cwes[0]
    if f.vuln_ids:
        return primary_vuln_id(f.vuln_ids) or f.vuln_ids[0]
    src = f.sources[0]
    return f"{src.tool}:{src.rule_id}"


def fingerprint(f: Finding) -> str:
    return _h(f.kind.value, vuln_key(f), f.path, f.anchor or str(f.start_line or ""))


def manifest_dir(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "" if parent == "." else parent


def cluster_key(f: Finding) -> tuple[str, ...]:
    if f.kind == Kind.DEPENDENCY:
        if f.sources[0].tool == "trivy-image":
            return (f.kind.value, f.path, "image")
        return (f.kind.value, manifest_dir(f.path), f.package or vuln_key(f))
    if f.kind == Kind.IAC:
        return (f.kind.value, f.path, vuln_key(f))
    if f.kind == Kind.LICENSE:
        return (f.kind.value, f.path, f.package or vuln_key(f))
    return (f.kind.value, f.path, f.anchor or str(f.start_line or ""))


# -- versions ---------------------------------------------------------------------------------


def _version(v: str | None) -> Version | None:
    if not v:
        return None
    v = v.strip().removeprefix("go").removeprefix("v")
    try:
        return Version(v)
    except InvalidVersion:
        m = re.match(r"(\d+(?:\.\d+)*)", v)
        try:
            return Version(m.group(1)) if m else None
        except InvalidVersion:
            return None


def best_fixed_version(installed: str | None, fixed: str | None) -> str | None:
    """Smallest listed fixed version above the installed one (fixes are often backported)."""
    if not fixed:
        return None
    candidates = [c.strip() for c in fixed.split(",") if c.strip()]
    cur = _version(installed)
    parsed = [(c, _version(c)) for c in candidates]
    above = [(c, v) for c, v in parsed if v is not None and (cur is None or v > cur)]
    if above:
        return min(above, key=lambda cv: cv[1])[0]
    return candidates[0] if candidates else None


def max_version(versions: list[str]) -> str | None:
    parsed = [(v, _version(v)) for v in versions if v]
    valid = [(v, pv) for v, pv in parsed if pv is not None]
    if valid:
        return max(valid, key=lambda vv: vv[1])[0]
    return versions[0] if versions else None


def is_breaking_upgrade(installed: str | None, target: str | None) -> bool | None:
    """Semver-ish: a major change, or a minor change while still on 0.x."""
    a, b = _version(installed), _version(target)
    if a is None or b is None:
        return None
    if a.major != b.major:
        return True
    return a.major == 0 and a.minor != b.minor


# -- merge ------------------------------------------------------------------------------------


def _merge(findings: list[Finding]) -> Finding:
    base = findings[0].model_copy(deep=True)
    for other in findings[1:]:
        base.sources.extend(other.sources)
        base.vuln_ids = sorted(set(base.vuln_ids) | set(other.vuln_ids))
        base.cwes = sorted(set(base.cwes) | set(other.cwes))
        base.severity = max_severity([base.severity, other.severity])
        base.reachable = merge_reachability([base.reachable, other.reachable])
        fixes = [best_fixed_version(f.installed_version, f.fixed_version) for f in (base, other)]
        known = [v for v in fixes if v]
        # merged advisories need the highest of their fixed versions
        base.fixed_version = max_version(known) if known else None
        base.installed_version = base.installed_version or other.installed_version
        base.call_path = base.call_path or other.call_path
        base.snippet = base.snippet or other.snippet
        if other.start_line and (not base.start_line or other.start_line < base.start_line):
            base.start_line, base.end_line = other.start_line, other.end_line
    return base


def _merge_dependency_aliases(findings: list[Finding]) -> list[Finding]:
    """Trivy says CVE-X, govulncheck says GO-Y (aliases CVE-X): same vulnerability.

    Within one (manifest dir, package) group, findings sharing any vulnerability id are merged.
    """
    out: list[Finding] = []
    groups: dict[tuple[str, ...], list[Finding]] = {}
    for f in findings:
        if f.kind == Kind.DEPENDENCY:
            groups.setdefault(cluster_key(f), []).append(f)
        else:
            out.append(f)
    for group in groups.values():
        merged: list[Finding] = []
        for f in group:
            target = next((m for m in merged if set(m.vuln_ids) & set(f.vuln_ids)), None)
            if target is None:
                merged.append(f.model_copy(deep=True))
            else:
                idx = merged.index(target)
                merged[idx] = _merge([target, f])
        out.extend(merged)
    return out


def _cluster_title(kind: Kind, members: list[Finding], c: dict) -> str:
    if kind == Kind.DEPENDENCY:
        ids = sorted({primary_vuln_id(f.vuln_ids) or f.rule_ids[0] for f in members})
        shown = ", ".join(ids[:3]) + (f" +{len(ids) - 3}" if len(ids) > 3 else "")
        target = f" -> {c['target_version']}" if c.get("target_version") else ""
        pkg = c.get("package") or "dependency"
        version = f" {c['installed_version']}" if c.get("installed_version") else ""
        return f"{pkg}{version}{target}: {shown}"
    lead = max(members, key=lambda f: f.severity.rank)
    line = f":{lead.start_line}" if lead.start_line else ""
    return f"{lead.title} ({lead.path}{line})"


def build_clusters(findings: list[Finding]) -> list[Cluster]:
    groups: dict[tuple[str, ...], list[Finding]] = {}
    for f in findings:
        groups.setdefault(cluster_key(f), []).append(f)
    clusters = []
    for key, members in groups.items():
        members.sort(key=lambda f: (-f.severity.rank, f.path, f.start_line or 0))
        kind = Kind(key[0])
        info: dict = {}
        if kind == Kind.DEPENDENCY:
            installed = next((f.installed_version for f in members if f.installed_version), None)
            fixes = [best_fixed_version(f.installed_version, f.fixed_version) for f in members]
            target = max_version([v for v in fixes if v])
            info = {
                "package": members[0].package,
                "installed_version": installed,
                "target_version": target,
                "breaking_upgrade": is_breaking_upgrade(installed, target),
            }
        lead = members[0]
        clusters.append(
            Cluster(
                id=_h(*key, n=12),
                kind=kind,
                key="|".join(key),
                title=_cluster_title(kind, members, info),
                severity=max_severity([f.severity for f in members]),
                reachable=merge_reachability([f.reachable for f in members]),
                path=lead.path,
                start_line=lead.start_line,
                findings=members,
                **info,
            )
        )
    clusters.sort(key=lambda c: (-c.severity.rank, -c.reachable.rank, c.kind.value, c.path))
    return clusters


def normalise(
    sarif_files: list[Path],
    repo_root: Path,
    cfg: SecfixConfig,
    tool_status: dict[str, str] | None = None,
) -> ScanReport:
    skip = cfg.skip_spec()
    raw: list[Finding] = []
    for path in sorted(sarif_files):
        raw.extend(parse_sarif(path, repo_root))
    kept = [f for f in raw if not skip.match_file(f.path)]
    by_fp: dict[str, list[Finding]] = {}
    for f in kept:
        f.fingerprint = fingerprint(f)
        by_fp.setdefault(f.fingerprint, []).append(f)
    deduped = [_merge(group) for group in by_fp.values()]
    deduped = _merge_dependency_aliases(deduped)
    for f in deduped:
        f.fingerprint = fingerprint(f)
    deduped.sort(key=lambda f: (-f.severity.rank, f.path, f.start_line or 0))
    return ScanReport(
        raw_results=len(raw),
        findings=deduped,
        clusters=build_clusters(deduped),
        tool_status=tool_status or {},
    )


def severity_counts(clusters: list[Cluster]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for c in clusters:
        counts[c.severity.value] += 1
    return counts
