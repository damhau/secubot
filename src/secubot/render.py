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
    dismissed_ttl_days: int = 180,
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
        "- **False positive or accepted risk:** close this issue as **Not planned**, with a "
        f"comment saying why. secubot then leaves the finding alone for {dismissed_ttl_days} "
        "days (`policy.dismissed_ttl_days`) and examines it again after that.\n"
        "- **Real issue:** fix it and close this issue as completed. If the finding is still "
        "reported after the cool-down, secubot tries again.\n"
        "- **Hard-coded secret:** rotate it first, then remove it from the code and history.\n"
        "- **Permanent exception** (a whole directory, a rule): add a suppression to "
        "`.secfix.yml`, which goes through review like any change."
    )
    parts.append(footer(cluster, cost, model, denied))
    return "\n\n".join(parts)[:65000]


VERDICTS = {"true_positive": "real", "false_positive": "false positive", "uncertain": "uncertain"}
STEP_LABELS = {"build": "build", "test": "tests", "rescan": "rescan"}
NO_EXAMPLES = {"severity", "kind"}


def short(text: str | None, limit: int = 90) -> str:
    """One line for a table cell, cut on a word boundary with an ellipsis."""
    one = " ".join(_CONTROL.sub("", text or "").split())
    if len(one) > limit:
        cut = one[: limit - 1]
        space = cut.rfind(" ")
        if space > limit // 2:
            cut = cut[:space]
        one = cut.rstrip(" ,.;:-") + "…"
    return inline(one, limit + 10)


def _label(c: Cluster) -> str:
    """What the finding is, without its location: `anyio 4.13.0 → 4.14.2`, a rule title."""
    if c.kind == Kind.DEPENDENCY and c.package:
        return f"{c.package} {c.installed_version or '?'} → {c.target_version or 'no fix yet'}"
    return re.sub(r"\s*\([^()]*:\d+\)$", "", c.title)


def _finding_cell(c: Cluster) -> str:
    if c.kind == Kind.DEPENDENCY and c.package:
        cves = [v for v in c.vuln_ids if v.startswith("CVE-")] or c.vuln_ids  # aliases: noise
        ids = ", ".join(cves[:3]) + (f" +{len(cves) - 3}" if len(cves) > 3 else "")
        head = f"**{short(c.package, 40)}** {short(_label(c)[len(c.package) + 1 :], 50)}"
        return f"{head}<br>{short(ids, 80)}" if ids else head
    loc = f"{c.path}:{c.start_line}" if c.start_line else c.path
    return f"**{short(_label(c), 70)}**<br>{code(loc)}"


def _checks(fix: FixResult) -> str:
    steps = fix.attempts[-1].steps if fix.attempts else []
    return " · ".join(
        f"{STEP_LABELS.get(st.name, short(st.name, 20))} {'✓' if st.ok else '✗'}" for st in steps
    )


def _issue_why(c: Cluster, t: TriageResult | None, fix: FixResult | None) -> str:
    if fix and fix.status != "fixed":
        return f"fix {fix.status}, {short(fix.reason, 70)}"
    if t is None:
        return ""
    if "prompt injection" in t.reason:
        return "possible prompt injection, read the cited file"
    if c.kind == Kind.SECRET:
        return "rotate the secret, then remove it"
    if t.final_verdict == "false_positive":
        if "auto-suppression disabled" in t.reason:
            return "confirm the false positive (auto-suppression is off)"
        return f"confirm the false positive ({c.severity.value}: too severe to auto-suppress)"
    if t.final_verdict == "uncertain":
        return "triage could not decide, needs a human"
    return short(t.reason, 70)


def _outcome(
    c: Cluster, t: TriageResult | None, fix: FixResult | None, acts: list[dict], dry_run: bool
) -> str:
    by_type = {a.get("type"): a for a in acts}

    def link(kind: str, label: str) -> str:
        url = str(by_type[kind].get("url") or "")
        if url.startswith("https://"):
            return f"[{label}]({url})"
        return f"{label} (dry run)" if dry_run else label

    if "pull_request" in by_type:
        checks = _checks(fix) if fix else ""
        return link("pull_request", "draft PR") + (f": {checks}" if checks else "")
    if "issue" in by_type:
        why = _issue_why(c, t, fix)
        return link("issue", "issue") + (f": {why}" if why else "")
    if "suppressed" in by_type:
        return "suppressed" + (" (dry run)" if dry_run else "")
    if "deferred" in by_type:
        return "next run (`policy.max_prs`, or the fix job failed)"
    for kind in ("error", "retry"):
        if kind in by_type:
            return f"{kind}: {short(by_type[kind].get('detail'), 80)}"
    if t is None:
        return "not triaged"
    if t.action == "fix" and fix:
        return f"fix {fix.status}"
    return t.action  # publish did not run


def _verdict(t: TriageResult) -> str:
    if t.action == "error":
        return "triage error"
    verdict = VERDICTS.get(t.final_verdict or "", t.final_verdict or "?")
    conf = t.analysis.confidence if t.analysis else ""
    return f"{verdict} ({conf})" if conf else verdict


def _examples(clusters: list[Cluster], limit: int = 3) -> str:
    counts: dict[str, int] = {}
    for c in clusters:
        counts[_label(c)] = counts.get(_label(c), 0) + 1
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    parts = [(f"{n}× " if n > 1 else "") + short(label, 60) for label, n in top]
    more = len(counts) - len(top)
    return " · ".join(parts) + (f" · +{more} more" if more > 0 else "")


def summary_markdown(
    report: ScanReport,
    selection: Selection | None = None,
    triage: dict[str, TriageResult] | None = None,
    fixes: dict[str, FixResult] | None = None,
    actions: list[dict] | None = None,
    repository: str = "",
    dry_run: bool = False,
) -> str:
    """The job summary: what secubot did, why, and what it left alone (grouped)."""
    from secubot.state import SKIP_GROUPS

    triage, fixes, actions = triage or {}, fixes or {}, actions or []
    by_cluster: dict[str, list[dict]] = {}
    for a in actions:
        by_cluster.setdefault(str(a.get("cluster_id", "")), []).append(a)
    clusters = {c.id: c for c in report.clusters}

    out = [f"# secubot · {inline(repository, 100)}" if repository else "# secubot", ""]
    if dry_run:
        out += ["> **Dry run.** Nothing was pushed or opened; outcomes show what would happen.", ""]

    counts = {"pull_request": 0, "issue": 0, "suppressed": 0, "deferred": 0, "error": 0}
    for a in actions:
        kind = "error" if a.get("type") == "retry" else a.get("type")
        if kind in counts and a.get("cluster_id") != "-":
            counts[kind] += 1
    names = {
        "pull_request": "draft PR",
        "issue": "issue",
        "suppressed": "suppressed",
        "deferred": "deferred",
        "error": "error",
    }
    plural = {"draft PR": "draft PRs", "issue": "issues", "error": "errors"}
    headline = [
        f"{n} {plural.get(names[k], names[k]) if n > 1 else names[k]}"
        for k, n in counts.items()
        if n
    ]
    cost = sum(t.cost_usd for t in triage.values()) + sum(f.cost_usd for f in fixes.values())
    tail = [f"{len(triage)} triaged"] if triage else ["nothing new to triage"]
    if cost:
        tail.append(f"cost ${cost:.2f}")
    parts = [f"**{' · '.join(headline)}**"] if headline else []
    out += [" · ".join([*parts, *tail]), ""]

    tools = " · ".join(
        f"{inline(name, 40)} {'✓' if status == 'ok' else '✗'}"
        for name, status in sorted(report.tool_status.items())
    )
    out.append(
        f"Scanned {report.raw_results} results → {len(report.clusters)} distinct findings"
        + (f" · {tools}" if tools else "")
    )
    out += [
        f"- **{inline(name, 40)} failed**: {short(status, 200)}"
        for name, status in sorted(report.tool_status.items())
        if status != "ok"
    ]

    handled = sorted(
        (clusters[cid] for cid in triage if cid in clusters),
        key=lambda c: (-c.severity.rank, c.id),
    )
    if handled:
        out += [
            "",
            "## Handled this run",
            "",
            "| Finding | Severity | Verdict | Outcome |",
            "|---|---|---|---|",
        ]
        for c in handled:
            t, fix = triage[c.id], fixes.get(c.id)
            out.append(
                f"| {_finding_cell(c)} | {c.severity.value} | {_verdict(t)} | "
                f"{_outcome(c, t, fix, by_cluster.get(c.id, []), dry_run)} |"
            )
        out += ["", "<details><summary>Triage reasoning</summary>", ""]
        for c in handled:
            t = triage[c.id]
            if t.analysis:
                why = short(t.analysis.reasoning, 450)
            else:
                why = short(t.error or t.reason, 300)
            review = ""
            if t.challenge:
                review = (
                    " Adversarial review: overturned."
                    if t.challenge.challenge_holds
                    else " Adversarial review: upheld."
                )
            out += [f"**{short(_label(c), 80)}** ({code(c.id)}): {why}{review}", ""]
        out.append("</details>")

    if selection:
        skipped: dict[str, list[Cluster]] = {}
        for d in selection.decisions:
            if not d.selected and d.cluster_id in clusters:
                skipped.setdefault(d.group or "other", []).append(clusters[d.cluster_id])
        if skipped:
            out += [
                "",
                "## Not handled this run",
                "",
                "| Why | Findings | Examples |",
                "|---|--:|---|",
            ]
            order = [*SKIP_GROUPS, *sorted(set(skipped) - set(SKIP_GROUPS))]
            for group in order:
                if group not in skipped:
                    continue
                label = SKIP_GROUPS.get(group, "Other")
                ex = "" if group in NO_EXAMPLES else _examples(skipped[group])
                out.append(f"| {label} | {len(skipped[group])} | {ex} |")

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

    notes = []
    for a in by_cluster.get("-", []):
        if a.get("type") == "state":
            notes.append(f"Suppressions on `secfix-state`: {short(a.get('detail'), 80)}.")
        elif a.get("type") == "ignored":
            notes.append(f"Publish ignored an artifact: {short(a.get('detail'), 150)}.")
        else:
            notes.append(f"{inline(a.get('type'), 30)}: {short(a.get('detail'), 150)}")
    if notes:
        out += ["", *[f"- {n}" for n in notes]]
    return "\n".join(out)
