"""Prompt templates and rendering. Untrusted data is always wrapped and neutralised here."""

from __future__ import annotations

import json
import re
from importlib.resources import files

from secubot.models import Cluster, Kind

_TAG_RE = re.compile(r"<\s*/?\s*untrusted\s*>", re.IGNORECASE)


def load(name: str) -> str:
    return (files(__package__) / f"{name}.md").read_text(encoding="utf-8")


def render(template: str, **values: str) -> str:
    """`{name}` substitution that leaves every other brace alone (code has braces)."""
    out = template
    for key, value in values.items():
        out = out.replace("{" + key + "}", value)
    return out


def neutralise(text: str, limit: int = 20_000) -> str:
    """Stop untrusted text from closing or opening an <untrusted> block."""
    text = _TAG_RE.sub("[tag removed]", text or "")
    if len(text) > limit:
        text = text[:limit] + "\n[... truncated ...]"
    return text


def finding_block(cluster: Cluster) -> str:
    """The finding as the agent sees it: structured facts plus raw scanner messages."""
    facts = {
        "cluster_id": cluster.id,
        "title": cluster.title,
        "kind": cluster.kind.value,
        "scanner_severity": cluster.severity.value,
        "reachability_from_scanners": cluster.reachable.value,
        "tools": cluster.tools,
        "rules": cluster.rule_ids,
        "vulnerabilities": cluster.vuln_ids,
        "cwes": cluster.cwes,
        "primary_location": f"{cluster.path}:{cluster.start_line}"
        if cluster.start_line
        else cluster.path,
    }
    if cluster.kind == Kind.DEPENDENCY:
        facts.update(
            package=cluster.package,
            installed_version=cluster.installed_version,
            target_version=cluster.target_version,
            breaking_upgrade=cluster.breaking_upgrade,
        )
    locations = []
    seen_advisories: set[str] = set()  # one copy per rule text, not per location
    for f in cluster.findings[:15]:
        loc = {
            "path": f.path,
            "line": f.start_line,
            "title": f.title,
            "severity": f.severity.value,
            "vulnerabilities": f.vuln_ids,
            "fixed_version": f.fixed_version,
            "snippet": f.snippet,
            "call_path": f.call_path,
            "scanner_messages": [
                {"tool": s.tool, "rule": s.rule_id, "message": s.message[:1500]}
                for s in f.sources[:5]
            ],
        }
        advisories = []
        for s in f.sources[:5]:
            if s.description and s.description not in seen_advisories:
                seen_advisories.add(s.description)
                advisories.append({"rule": s.rule_id, "text": s.description})
        loc["advisories"] = advisories
        locations.append({k: v for k, v in loc.items() if v not in (None, [], "")})
    body = json.dumps({"facts": facts, "locations": locations}, indent=2, ensure_ascii=False)
    return (
        "<untrusted>\n### Finding (scanner output, normalised)\n\n```json\n"
        + neutralise(body)
        + "\n```\n</untrusted>"
    )
