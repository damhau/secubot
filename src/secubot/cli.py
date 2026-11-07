"""secubot command line. Each pipeline stage is one subcommand; the workflow chains them."""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import sys
from collections import Counter
from pathlib import Path

from secubot import __version__
from secubot.config import detect_languages, load_config, node_version_file


def _gh_output(**values: object) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    lines = []
    for key, value in values.items():
        text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
        if "\n" in text:
            raise ValueError(f"output {key} must be a single line")
        lines.append(f"{key}={text}")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    else:
        print("\n".join(lines))


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _repo(args) -> Path:
    return Path(args.repo).resolve()


def _cfg(args):
    return load_config(_repo(args), args.config)


# -- stages -----------------------------------------------------------------------------------


def cmd_config_check(args) -> int:
    cfg = _cfg(args)
    from secubot.scanners import enabled_tools

    print(
        json.dumps(
            {
                "languages": detect_languages(_repo(args), cfg),
                "tools": enabled_tools(_repo(args), cfg),
                "config": cfg.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def cmd_detect(args) -> int:
    from secubot.scanners import enabled_tools

    cfg = _cfg(args)
    langs = detect_languages(_repo(args), cfg)
    tools = enabled_tools(_repo(args), cfg)
    node_version = node_version_file(_repo(args), cfg) if "node" in langs else ""
    if args.github_output:
        _gh_output(
            languages=langs,
            tools=tools,
            go=str("go" in langs).lower(),
            python=str("python" in langs).lower(),
            node=str("node" in langs).lower(),
            node_version_file=node_version,
            image=str("trivy-image" in tools).lower(),
        )
    else:
        print(json.dumps({"languages": langs, "tools": tools, "node_version_file": node_version}))
    return 0


def cmd_scan(args) -> int:
    from secubot.scanners import enabled_tools, run_scanners

    cfg = _cfg(args)
    tools = args.tools.split(",") if args.tools else enabled_tools(_repo(args), cfg)
    out = Path(args.out)
    statuses = run_scanners(tools, _repo(args), out, cfg)
    status = {s.tool: ("ok" if s.ok else f"failed: {s.detail[-400:]}") for s in statuses}
    _write_json(out / "status.json", status)
    for tool, st in status.items():
        print(f"{tool}: {st}", file=sys.stderr)
    if args.strict and any(not s.ok for s in statuses):
        return 1
    return 0


def cmd_normalise(args) -> int:
    from secubot.normalise import normalise, severity_counts

    cfg = _cfg(args)
    sarif_dir = Path(args.sarif_dir)
    status_file = sarif_dir / "status.json"
    status = json.loads(status_file.read_text()) if status_file.is_file() else {}
    report = normalise(sorted(sarif_dir.glob("*.sarif")), _repo(args), cfg, status)
    report.base_sha = args.base_sha or ""
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(report.model_dump_json(indent=2), encoding="utf-8")
    counts = severity_counts(report.clusters)
    print(
        f"{report.raw_results} results -> {len(report.findings)} findings -> "
        f"{len(report.clusters)} clusters {counts}",
        file=sys.stderr,
    )
    return 0


def cmd_select(args) -> int:
    from secubot.models import ScanReport
    from secubot.state import RepoState, select

    cfg = _cfg(args)
    report = ScanReport.model_validate_json(Path(args.report).read_text())
    state = RepoState.load(Path(args.state_dir)) if args.state_dir else RepoState()
    selection = select(report, state, cfg)
    Path(args.out).write_text(selection.model_dump_json(indent=2), encoding="utf-8")
    skipped: Counter[str] = Counter()
    for d in selection.decisions:
        if d.selected:
            print(f"{d.cluster_id} SELECTED", file=sys.stderr)
        else:  # grouped by the reason's stable prefix (reasons embed dates and branch names)
            skipped[d.reason.split(":")[0].split(" (")[0].split(" secfix/")[0]] += 1
    for reason, n in skipped.most_common():
        print(f"{n:5d} skipped: {reason}", file=sys.stderr)
    if args.github_output:
        _gh_output(
            count=str(len(selection.selected)),
            has_work=str(bool(selection.selected)).lower(),
            has_resolved=str(bool(selection.resolved)).lower(),
        )
    if selection.resolved:
        print(f"{len(selection.resolved):5d} open issue/PR no longer reported", file=sys.stderr)
    if selection.resolved_note:
        print(f"auto-close held back: {selection.resolved_note}", file=sys.stderr)
    return 0


def cmd_triage(args) -> int:
    from secubot.agent import claude_session
    from secubot.models import ScanReport
    from secubot.state import Selection
    from secubot.triage import triage_cluster

    cfg = _cfg(args)
    scan = Path(args.scan_dir)
    report = ScanReport.model_validate_json((scan / "report.json").read_text())
    selection = Selection.model_validate_json((scan / "selection.json").read_text())
    out = Path(args.out)
    results = []

    async def run_all():
        for cid in selection.selected:
            cluster = report.cluster(cid)
            print(f"triage {cid}: {cluster.title}", file=sys.stderr)
            try:
                r = await triage_cluster(cluster, cfg, _repo(args), claude_session)
            except Exception as exc:  # noqa: BLE001 - one cluster must not stop the others
                from secubot.triage import TriageResult

                r = TriageResult(
                    cluster_id=cid,
                    action="error",
                    reason="triage crashed",
                    error=f"{type(exc).__name__}: {exc}"[:500],
                )
            print(f"  -> {r.action} ({r.reason}) ${r.cost_usd:.2f}", file=sys.stderr)
            results.append(r)

    asyncio.run(run_all())
    _write_json(out / "triage.json", [r.model_dump(mode="json") for r in results])
    to_fix = [r.cluster_id for r in results if r.action == "fix"][: cfg.policy.max_prs]
    publish = any(r.action in {"fix", "suppress", "issue"} for r in results)
    if args.github_output:
        _gh_output(
            fix_matrix=to_fix, has_fixes=str(bool(to_fix)).lower(), has_publish=str(publish).lower()
        )
    else:
        print(json.dumps({"fix": to_fix}))
    errors = [r for r in results if r.action == "error"]
    if results and len(errors) == len(results):
        # Nothing was triaged, so nothing gets fixed or published. A missing or rejected API
        # key looks like this, and would otherwise be a green run that cost $0 and did nothing.
        # With only some errors the job stays green: failing it would drop the good results.
        print(
            f"error: triage failed for all {len(results)} selected findings: {errors[0].error}",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_fix(args) -> int:
    from secubot.agent import claude_session
    from secubot.fix import fix_cluster, make_verifier
    from secubot.models import ScanReport
    from secubot.triage import TriageResult

    cfg = _cfg(args)
    scan = Path(args.scan_dir)
    report = ScanReport.model_validate_json((scan / "report.json").read_text())
    triage = {
        t["cluster_id"]: TriageResult.model_validate(t)
        for t in json.loads((Path(args.triage_dir) / "triage.json").read_text())
    }
    if args.cluster not in triage or triage[args.cluster].action != "fix":
        print(f"cluster {args.cluster} was not triaged for fixing", file=sys.stderr)
        return 2
    cluster = report.cluster(args.cluster)
    out = Path(args.out)
    verifier = make_verifier(cfg, _repo(args), report, out / "verify")
    result = asyncio.run(
        fix_cluster(
            cluster,
            triage[args.cluster],
            cfg,
            _repo(args),
            out,
            claude_session,
            verifier,
            scan_dir=scan,
        )
    )
    print(
        f"fix {cluster.id}: {result.status} ({result.reason}) ${result.cost_usd:.2f}",
        file=sys.stderr,
    )
    return 0


def cmd_recheck(args) -> int:
    """Called by the agent (allowed Bash command) to re-run the relevant scanners."""
    from secubot.fix import recheck
    from secubot.models import ScanReport

    cid = os.environ.get("SECUBOT_RECHECK_CLUSTER")
    scan = os.environ.get("SECUBOT_SCAN_DIR")
    root = Path(os.environ.get("SECUBOT_REPO_ROOT") or ".").resolve()
    if not cid or not scan:
        print("recheck is only available inside a secubot fix session", file=sys.stderr)
        return 2
    report = ScanReport.model_validate_json((Path(scan) / "report.json").read_text())
    cfg = load_config(root)
    print(recheck(report.cluster(cid), report, cfg, root))
    return 0


def cmd_publish(args) -> int:
    from secubot.publish import Publisher, Runner, load_inputs

    cfg = _cfg(args)
    inputs = load_inputs(
        Path(args.scan_dir),
        Path(args.triage_dir) if args.triage_dir else None,
        Path(args.fix_dir) if args.fix_dir else None,
    )
    publisher = Publisher(
        runner=Runner(cwd=_repo(args), dry_run=args.dry_run),
        cfg=cfg,
        inputs=inputs,
        base_branch=args.base_branch or os.environ.get("GITHUB_REF_NAME", "main"),
        instance=args.instance,
        server=os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
        repo=os.environ.get("GITHUB_REPOSITORY", ""),
        run_id=os.environ.get("GITHUB_RUN_ID", ""),
        git_name=os.environ.get("SECUBOT_GIT_NAME", "github-actions[bot]"),
        git_email=os.environ.get(
            "SECUBOT_GIT_EMAIL", "41898282+github-actions[bot]@users.noreply.github.com"
        ),
    )
    actions = publisher.run()
    out = Path(args.out)
    _write_json(
        out / "publish.json",
        {
            "secubot": __version__,
            "repository": publisher.repo,
            "run_id": publisher.run_id,
            "generated_at": dt.datetime.now(dt.UTC).isoformat(),
            "dry_run": args.dry_run,
            "actions": actions,
        },
    )
    if args.dry_run:
        for call in publisher.runner.calls:
            print("[dry-run]", " ".join(call)[:300], file=sys.stderr)
    for a in actions:
        print(
            f"{a['type']}: {a['cluster_id']} {a.get('url') or a.get('detail', '')}", file=sys.stderr
        )
    return 1 if any(a["type"] == "error" for a in actions) else 0


def cmd_summary(args) -> int:
    from secubot import render
    from secubot.fix import FixResult
    from secubot.models import ScanReport
    from secubot.report import fleet_entry
    from secubot.state import Selection
    from secubot.triage import TriageResult

    scan = Path(args.scan_dir)
    report = ScanReport.model_validate_json((scan / "report.json").read_text())
    sel_file = scan / "selection.json"
    selection = Selection.model_validate_json(sel_file.read_text()) if sel_file.is_file() else None
    triage = {}
    if args.triage_dir and (Path(args.triage_dir) / "triage.json").is_file():
        for t in json.loads((Path(args.triage_dir) / "triage.json").read_text()):
            tr = TriageResult.model_validate(t)
            triage[tr.cluster_id] = tr
    fixes = {}
    if args.fix_dir and Path(args.fix_dir).is_dir():
        for f in Path(args.fix_dir).glob("**/result.json"):
            fr = FixResult.model_validate_json(f.read_text())
            fixes[fr.cluster_id] = fr
    actions = []
    published: dict = {}
    if args.publish_dir and (Path(args.publish_dir) / "publish.json").is_file():
        published = json.loads((Path(args.publish_dir) / "publish.json").read_text())
        actions = published.get("actions", [])
    md = render.summary_markdown(
        report,
        selection,
        triage,
        fixes,
        actions,
        repository=published.get("repository") or os.environ.get("GITHUB_REPOSITORY", ""),
        dry_run=bool(published.get("dry_run")),
    )
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")
    else:
        print(md)
    if args.out:
        _write_json(Path(args.out), fleet_entry(report, selection, triage, fixes, actions))
    return 0


def cmd_pip_audit_sarif(args) -> int:
    from secubot.pip_audit import pip_audit_to_sarif

    doc = pip_audit_to_sarif(
        json.loads(Path(args.input).read_text()), args.source, Path(args.repo).resolve()
    )
    _write_json(Path(args.out), doc)
    return 0


def cmd_fleet_dispatch(args) -> int:
    from secubot.fleet import dispatch, load_fleet

    fleet = load_fleet(Path(args.fleet))
    done = dispatch(
        fleet,
        now=dt.datetime.now(dt.UTC),
        dispatch_all=args.all,
        dry_run=args.dry_run,
        only=args.repo_filter,
    )
    for line in done:
        print(line)
    # The other repositories were still dispatched; this makes the failed one visible.
    return 1 if any(": FAILED: " in line for line in done) else 0


def cmd_fleet_report(args) -> int:
    from secubot.fleet import collect, load_fleet, render_dashboard, unhealthy

    fleet = load_fleet(Path(args.fleet))
    entries = collect(fleet, Path(args.out))
    md = render_dashboard(entries)
    (Path(args.out) / "dashboard.md").write_text(md, encoding="utf-8")
    _write_json(Path(args.out) / "fleet.json", entries)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")
    else:
        print(md)
    # Runs started by the dispatch App notify nobody, so this job's failure is the alert.
    if bad := unhealthy(entries):
        print(f"error: latest run needs attention: {', '.join(bad)}", file=sys.stderr)
        return 1
    return 0


# -- parser -----------------------------------------------------------------------------------


def cmd_onboard(args) -> int:
    from secubot.onboard.wizard import run

    return run(args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secubot", description=__doc__)
    p.add_argument("--version", action="version", version=f"secubot {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, func, help_text, repo=True):
        sp = sub.add_parser(name, help=help_text)
        if repo:
            sp.add_argument("--repo", default=".", help="target repository checkout")
            sp.add_argument("--config", default=None, help="path relative to --repo")
        sp.set_defaults(func=func)
        return sp

    add("config-check", cmd_config_check, "validate .secfix.yml and show the effective config")

    sp = add("detect", cmd_detect, "detect languages and enabled scanners")
    sp.add_argument("--github-output", action="store_true")

    sp = add("scan", cmd_scan, "run the scanners, write one SARIF file per tool")
    sp.add_argument("--out", required=True)
    sp.add_argument("--tools", default="", help="comma-separated subset")
    sp.add_argument("--strict", action="store_true", help="fail if any scanner fails")

    sp = add("normalise", cmd_normalise, "parse, dedup and cluster SARIF into report.json")
    sp.add_argument("--sarif-dir", required=True)
    sp.add_argument("--out", required=True)
    sp.add_argument("--base-sha", default=os.environ.get("GITHUB_SHA", ""))

    sp = add("select", cmd_select, "drop known/suppressed/in-flight clusters, cap to top N")
    sp.add_argument("--report", required=True)
    sp.add_argument("--state-dir", default=None)
    sp.add_argument("--out", required=True)
    sp.add_argument("--github-output", action="store_true")

    sp = add("triage", cmd_triage, "read-only Claude triage with adversarial review")
    sp.add_argument("--scan-dir", required=True)
    sp.add_argument("--out", required=True)
    sp.add_argument("--github-output", action="store_true")

    sp = add("fix", cmd_fix, "fix one cluster with Claude, verify, write patch.diff")
    sp.add_argument("--scan-dir", required=True)
    sp.add_argument("--triage-dir", required=True)
    sp.add_argument("--cluster", required=True)
    sp.add_argument("--out", required=True)

    add("recheck", cmd_recheck, "re-run the scanners for the cluster being fixed", repo=False)

    sp = add("publish", cmd_publish, "validate patches, open draft PRs/issues, update state")
    sp.add_argument("--scan-dir", required=True)
    sp.add_argument("--triage-dir", default=None)
    sp.add_argument("--fix-dir", default=None)
    sp.add_argument("--out", required=True)
    sp.add_argument("--base-branch", default=None)
    sp.add_argument(
        "--instance", default="", help="workflow `instance` input; scopes auto-close in a monorepo"
    )
    sp.add_argument("--dry-run", action="store_true")

    sp = add("summary", cmd_summary, "job summary markdown (+ fleet entry JSON)", repo=False)
    sp.add_argument("--scan-dir", required=True)
    sp.add_argument("--triage-dir", default=None)
    sp.add_argument("--fix-dir", default=None)
    sp.add_argument("--publish-dir", default=None)
    sp.add_argument("--out", default=None, help="write the machine-readable run report here")

    sp = add("pip-audit-sarif", cmd_pip_audit_sarif, "convert pip-audit JSON to SARIF")
    sp.add_argument("--input", required=True)
    sp.add_argument("--source", required=True, help="requirements file, repo-relative")
    sp.add_argument("--out", required=True)

    sp = add("fleet-dispatch", cmd_fleet_dispatch, "dispatch staggered runs", repo=False)
    sp.add_argument("--fleet", required=True)
    sp.add_argument("--all", action="store_true", help="ignore the stagger slots")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--repo-filter", default=None, help="only this owner/name")

    sp = add("fleet-report", cmd_fleet_report, "collect run reports into a dashboard", repo=False)
    sp.add_argument("--fleet", required=True)
    sp.add_argument("--out", required=True)

    sp = add(
        "onboard",
        cmd_onboard,
        "wizard: set secubot up on a GitHub repository (secrets, settings, files, PR)",
        repo=False,
    )
    sp.add_argument("target", metavar="OWNER/REPO")
    sp.add_argument("--yes", action="store_true", help="take every default, ask nothing")
    sp.add_argument(
        "--dry-run", action="store_true", help="show the plan and files, change nothing"
    )
    sp.add_argument(
        "--config", help="TOML defaults (default: ~/.config/secubot/config.toml, $SECUBOT_CONFIG)"
    )
    sp.add_argument("--api-key-file", help="file with the Anthropic API key (replaces the secret)")
    sp.add_argument("--no-api-key", action="store_true", help="leave ANTHROPIC_API_KEY as it is")
    sp.add_argument("--app-id", help="GitHub App ID for publish")
    sp.add_argument("--app-key", help="the App's private key .pem")
    sp.add_argument("--no-app", action="store_true", help="don't set up a GitHub App")
    sp.add_argument(
        "--dependabot",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="add dependabot.yml and turn on alerts and security updates (default: yes)",
    )
    sp.add_argument("--setup", help="setup command (default: detected)")
    sp.add_argument("--build", help="build command (default: detected)")
    sp.add_argument("--test", help="test command (default: detected)")
    sp.add_argument("--skip", help="extra paths to skip, comma-separated")
    sp.add_argument("--branch", help="branch for the PR (default: secubot/onboarding)")
    sp.add_argument("--secubot-repo", help="central repository (default: damhau/secubot)")
    sp.add_argument("--ref", help="ref of the reusable workflow (default: the major, v1)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
