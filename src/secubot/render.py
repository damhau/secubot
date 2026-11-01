"""Markdown for PRs, issues and the job summary.

Everything that originates from the repository, the scanners or the model is untrusted and
is either sanitised (prose) or put in a code fence whose length is computed from its
content (so it cannot close the fence early). Sanitising neutralises @mentions (no pings),
issue references and closing keywords (no cross-linking or auto-closing), raw HTML and
markdown links/images (no tracking pixels, no disguised links).
"""

from __future__ import annotations

import re

from secubot import __version__
from secubot.fix import FixResult
from secubot.models import Cluster, Kind, ScanReport
from secubot.state import Selection
from secubot.triage import TriageResult

WJ = "⁠"  # word joiner: invisible, breaks GitHub's autolinking
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f‪-‮⁦-⁩]")
_MENTION = re.compile(r"@(?=[A-Za-z0-9_-])")
_ISSUE_REF = re.compile(r"(?<![A-Za-z0-9&])#(?=\d)")
_GH_REF = re.compile(r"\bGH-(?=\d)", re.IGNORECASE)
_SAFE_URL = re.compile(r"https://[A-Za-z0-9.\-]+(?:/[A-Za-z0-9._~/%=?&+:\-]*)?(?:#[\w\-]*)?")
_URL_SCHEME = re.compile(r"\b(https?|ftp|javascript|data|vbscript)(:)", re.IGNORECASE)


def sanitize(text: str | None, limit: int = 4000) -> str:
    text = _CONTROL.sub("", text or "")
    if len(text) > limit:
        text = text[:limit] + " [... truncated]"
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = _MENTION.sub("@" + WJ, text)
    text = _ISSUE_REF.sub("#" + WJ, text)
    text = _GH_REF.sub(lambda m: m.group(0) + WJ, text)
    text = text.replace("](", "]" + WJ + "(").replace("![", "!" + WJ + "[")
    text = _URL_SCHEME.sub(lambda m: m.group(1) + WJ + m.group(2), text)
    return text


def inline(text: str | None, limit: int = 300) -> str:
    """For table cells and titles: one line, no pipes or backticks."""
    one = " ".join(sanitize(text, limit).split())
    return one.replace("|", "\\|").replace("`", "'")


def code(text: str | None) -> str:
    """Inline code span safe for any content."""
    t = " ".join((text or "").split()).replace("`", "'")[:300]
    return f"`{t}`" if t else ""


def fence(text: str | None, lang: str = "", limit: int = 6000) -> str:
    text = _CONTROL.sub("", text or "")
    if len(text) > limit:
        text = "[... truncated ...]\n" + text[-limit:]
    longest = max((len(m) for m in re.findall(r"`{3,}|~{3,}", text)), default=2)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{lang}\n{text.rstrip()}\n{ticks}"


def title_for(cluster: Cluster, prefix: str = "") -> str:
    t = " ".join(cluster.title.split())[:100].replace("@", "@" + WJ)
    return f"{prefix}{t}"


def issue_title(cluster: Cluster) -> str:
    return title_for(cluster, f"[secfix:{cluster.id}] ")


def pr_title(cluster: Cluster) -> str:
    return title_for(cluster, "security: ")


def _links(cluster: Cluster, server: str, repo: str, run_id: str) -> list[str]:
    links = []
    if server and repo and run_id:
        links.append(
            f"- Scan run and SARIF files: {server}/{repo}/actions/runs/{run_id} "
            f"(artifact `secubot-sarif`)"
        )
    if server and repo:
        links.append(f"- Code scanning alerts: {server}/{repo}/security/code-scanning")
    seen = set()
    for f in cluster.findings:
        for s in f.sources:
            uri = s.help_uri or ""
            if _SAFE_URL.fullmatch(uri) and uri not in seen and len(seen) < 5:
                seen.add(uri)
                links.append(f"- {inline(s.tool, 40)} `{inline(s.rule_id, 80)}`: <{uri}>")
    return links


def finding_section(cluster: Cluster, server: str = "", repo: str = "", run_id: str = "") -> str:
    loc = f"{cluster.path}:{cluster.start_line}" if cluster.start_line else cluster.path
    rows = [
        ("Kind", cluster.kind.value),
        ("Scanner severity", cluster.severity.value),
        ("Reachable (scanners)", cluster.reachable.value),
        ("Tools", ", ".join(cluster.tools)),
        ("Rules", ", ".join(cluster.rule_ids[:10])),
        ("CWE", ", ".join(cluster.cwes)),
        ("Vulnerabilities", ", ".join(cluster.vuln_ids[:15])),
        ("Location", code(loc)),
    ]
    if cluster.kind == Kind.DEPENDENCY:
        rows += [
            ("Package", code(cluster.package)),
            ("Installed", code(cluster.installed_version)),
            ("Fixed in", code(cluster.target_version) or "no fixed release"),
            ("Major/breaking upgrade", str(cluster.breaking_upgrade).lower()),
        ]
    table = ["| | |", "|---|---|"]
    table += [f"| {k} | {v if v.startswith('`') else inline(v)} |" for k, v in rows if v]
    out = ["## Finding", "", f"**{inline(cluster.title, 200)}**", "", *table]
    locations = [
        f"- {code(f'{f.path}:{f.start_line}' if f.start_line else f.path)} "
        f"({inline(', '.join(f.tools), 80)}): {inline(f.title, 160)}"
        for f in cluster.findings[:10]
    ]
    if len(cluster.findings) > 1:
        out += ["", "<details><summary>All locations</summary>", "", *locations, "", "</details>"]
    links = _links(cluster, server, repo, run_id)
    if links:
        out += ["", *links]
    return "\n".join(out)


def triage_section(t: TriageResult | None) -> str:
    if t is None or t.analysis is None:
        return "## Triage\n\nNo triage result."
    a = t.analysis
    out = [
        "## Exploitability (triage)",
        "",
        f"Verdict **{t.final_verdict}** ({inline(t.reason, 200)}). Analysis: reachable "
        f"**{a.reachable}**, exploitable **{a.exploitable}**, severity **{a.severity.value}**, "
        f"confidence **{a.confidence}**.",
        "",
        sanitize(a.reasoning, 5000),
    ]
    if a.evidence:
        out += ["", "Evidence:"]
        out += [
            f"- {code(f'{e.path}:{e.line}' if e.line else e.path)}: {inline(e.note, 300)}"
            for e in a.evidence[:10]
        ]
    if t.challenge is not None:
        c = t.challenge
        out += [
            "",
            "<details><summary>Adversarial review "
            f"(challenge {'held' if c.challenge_holds else 'did not hold'}, "
            f"{c.confidence} confidence)</summary>",
            "",
            sanitize(c.arguments, 4000),
            "",
            "</details>",
        ]
    return "\n".join(out)


def verification_section(r: FixResult) -> str:
    final = r.attempts[-1] if r.attempts else None
    out = ["## Verification", ""]
    if final is None:
        return "\n".join([*out, "No verification was run."])
    out += [
        f"Attempt {final.number} of {len(r.attempts)}; checks re-run by the pipeline with a "
        "scrubbed environment (not self-reported by the agent).",
        "",
        "| Step | Command | Result | Time |",
        "|---|---|---|---|",
    ]
    for s in final.steps:
        mark = "pass" if s.ok else f"FAIL (exit {s.exit_code})"
        out.append(f"| {s.name} | {code(s.command)} | {mark} | {s.duration_s:.0f}s |")
    if not {"build", "test"} & {s.name for s in final.steps}:
        out.append(
            "\n**No build or test command is configured** (`commands.build` / `commands.test` "
            "in `.secfix.yml`): this change was verified by the re-scan only."
        )
    for p in final.problems:
        out.append(f"\n- {inline(p, 300)}")
    for s in final.steps:
        if s.output_tail.strip():
            out += [
                "",
                f"<details><summary>{s.name} output (tail)</summary>",
                "",
                fence(s.output_tail, limit=3000),
                "",
                "</details>",
            ]
    return "\n".join(out)


def changes_section(r: FixResult) -> str:
    out = ["## Changes", ""]
    if r.output is not None:
        out.append(sanitize(r.output.summary, 3000))
        if r.output.changes:
            out += ["", *[f"- {inline(c, 300)}" for c in r.output.changes[:20]]]
        if r.output.risk_notes.strip():
            out += ["", "**Risk notes:** " + sanitize(r.output.risk_notes, 2000)]
    if r.diffstat:
        out += ["", fence(r.diffstat)]
    return "\n".join(out)


def footer(cluster: Cluster, cost: float, model: str, denied: int) -> str:
    return "\n".join(
        [
            "---",
            f"<sub>secubot {__version__} · cluster `{cluster.id}` · model `{inline(model, 60)}` "
            f"· agent cost ${cost:.2f} · denied tool calls: {denied}. "
            "Opened as a draft by an automated pipeline: review the diff like any external "
            "contribution. secubot never merges. To silence this finding, close the PR "
            "(cool-down applies) or add a suppression with a reason and an expiry in "
            "`.secfix.yml`.</sub>",
            "",
            f"<!-- secubot:cluster={cluster.id} fingerprints={','.join(cluster.fingerprints)} -->",
        ]
    )


def pr_body(
    cluster: Cluster,
    triage: TriageResult | None,
    fix: FixResult,
    model: str,
    server: str = "",
    repo: str = "",
    run_id: str = "",
) -> str:
    cost = fix.cost_usd + (triage.cost_usd if triage else 0.0)
    denied = fix.denied_tool_calls + (triage.denied_tool_calls if triage else 0)
    parts = [
        "> [!IMPORTANT]\n> Automated security fix proposed by secubot. Draft: needs human "
        "review. Do not merge without reading the diff.",
        finding_section(cluster, server, repo, run_id),
        triage_section(triage),
        changes_section(fix),
        verification_section(fix),
        footer(cluster, cost, model, denied),
    ]
    return "\n\n".join(parts)[:65000]


def issue_body(
    cluster: Cluster,
    reason: str,
    triage: TriageResult | None = None,
    fix: FixResult | None = None,
    model: str = "",
    server: str = "",
    repo: str = "",
    run_id: str = "",
) -> str:
    cost = (fix.cost_usd if fix else 0.0) + (triage.cost_usd if triage else 0.0)
    denied = (fix.denied_tool_calls if fix else 0) + (triage.denied_tool_calls if triage else 0)
    parts = [
        f"secubot needs a human for this finding: **{inline(reason, 500)}**",
        finding_section(cluster, server, repo, run_id),
        triage_section(triage),
    ]
    if fix is not None:
        parts.append(f"## Fix attempt\n\nStatus **{fix.status}**: {sanitize(fix.reason, 2000)}")
        if fix.attempts:
            parts.append(verification_section(fix))
    parts.append(
        "## What to do\n\n"
        "- Real issue: fix it (or let secubot retry by closing this issue after the cool-down).\n"
        "- False positive: add a suppression to `.secfix.yml` with a reason and an expiry, "
        "then close this issue.\n"
        "- Hard-coded secret: rotate it first, then remove it from the code and history."
    )
    parts.append(footer(cluster, cost, model, denied))
    return "\n\n".join(parts)[:65000]


def summary_markdown(
    report: ScanReport,
    selection: Selection | None = None,
    triage: dict[str, TriageResult] | None = None,
    fixes: dict[str, FixResult] | None = None,
    actions: list[dict] | None = None,
) -> str:
    triage, fixes = triage or {}, fixes or {}
    out = [
        "# secubot",
        "",
        f"{report.raw_results} raw results → {len(report.findings)} findings → "
        f"{len(report.clusters)} clusters.",
        "",
        "| Tool | Status |",
        "|---|---|",
        *[f"| {inline(t, 40)} | {inline(s, 200)} |" for t, s in sorted(report.tool_status.items())],
        "",
        "| Cluster | Severity | Kind | Title | Decision |",
        "|---|---|---|---|---|",
    ]
    reasons = {d.cluster_id: d.reason for d in (selection.decisions if selection else [])}
    for c in report.clusters[:100]:
        decision = reasons.get(c.id, "")
        if c.id in triage:
            t = triage[c.id]
            decision = f"triage: {t.action} ({inline(t.reason, 120)})"
        if c.id in fixes:
            decision += f"; fix: {fixes[c.id].status}"
        out.append(
            f"| `{c.id}` | {c.severity.value} | {c.kind.value} | {inline(c.title, 100)} | "
            f"{inline(decision, 200) if c.id not in triage else decision} |"
        )
    if selection and selection.expired_suppressions:
        out += [
            "",
            "## Expired suppressions",
            "",
            "These no longer apply; renew or remove them:",
            "",
        ]
        out += [
            f"- {inline(x.id or x.rule or x.path or '', 80)} ({x.source}, expired {x.expires}): "
            f"{inline(x.reason, 200)}"
            for x in selection.expired_suppressions
        ]
    if actions:
        out += ["", "## Published", ""]
        out += [
            f"- {a['type']} for `{a['cluster_id']}`: {a.get('url') or a.get('detail', '')}"
            for a in actions
        ]
    return "\n".join(out)
