"""State and selection: keep only findings that are new, unsuppressed and not in flight.

State comes from four places, all fetched read-only by the scan job:
  * remote branches `secfix/<cluster id>`     -> work in flight (the idempotency key)
  * pull requests whose head is `secfix/...`  -> open = in flight, closed unmerged = rejected
  * issues titled `[secfix:<cluster id>] ...` -> open = waiting for a human
  * `suppressions.yml` on the `secfix-state` branch (agreed false positives, with expiry)
plus the human-curated `suppressions:` list in `.secfix.yml`.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

import pathspec
import yaml
from pydantic import BaseModel, Field

from secubot.config import SecfixConfig, Suppression
from secubot.models import BRANCH_PREFIX, Cluster, Kind, Reachability, ScanReport

ISSUE_TITLE_RE = re.compile(r"\[secfix:([0-9a-f]{12})\]")
STATE_BRANCH = "secfix-state"
STATE_FILE = "suppressions.yml"


class PullRef(BaseModel):
    number: int
    head: str
    state: str  # OPEN | CLOSED | MERGED
    closed_at: dt.datetime | None = None
    url: str = ""


class IssueRef(BaseModel):
    number: int
    title: str
    state: str  # OPEN | CLOSED
    state_reason: str = ""  # COMPLETED | NOT_PLANNED | DUPLICATE | REOPENED
    closed_at: dt.datetime | None = None
    url: str = ""
    comment: str = ""
    """Latest comment by the owner, an org member or a collaborator: why it was dismissed."""

    @property
    def dismissed(self) -> bool:
        """Closed as *not planned*: a maintainer says it's a false positive or accepted risk."""
        return self.state == "CLOSED" and self.state_reason == "NOT_PLANNED"

    @property
    def cluster_id(self) -> str | None:
        m = ISSUE_TITLE_RE.search(self.title)
        return m.group(1) if m else None


class RepoState(BaseModel):
    branches: set[str] = Field(default_factory=set)
    pulls: list[PullRef] = Field(default_factory=list)
    issues: list[IssueRef] = Field(default_factory=list)
    suppressions: list[Suppression] = Field(default_factory=list)  # from the state branch

    @classmethod
    def load(cls, state_dir: Path) -> RepoState:
        """Load what the workflow fetched with `gh` (missing files mean "no state yet")."""

        def read_json(name: str) -> Any:
            p = state_dir / name
            if not p.is_file() or not p.read_text().strip():
                return []
            return json.loads(p.read_text())

        branches = set()
        for ref in read_json("branches.json"):
            name = ref.get("ref", "") if isinstance(ref, dict) else str(ref)
            branches.add(name.removeprefix("refs/heads/"))
        pulls = [
            PullRef(
                number=p["number"],
                head=p.get("headRefName", ""),
                state="MERGED" if p.get("mergedAt") else str(p.get("state", "")).upper(),
                closed_at=p.get("closedAt") or None,
                url=p.get("url", ""),
            )
            for p in read_json("pulls.json")
        ]
        issues = [
            IssueRef(
                number=i["number"],
                title=i.get("title", ""),
                state=str(i.get("state", "")).upper(),
                state_reason=str(i.get("stateReason") or "").upper(),
                closed_at=i.get("closedAt") or None,
                url=i.get("url", ""),
                comment=_maintainer_comment(i.get("comments") or []),
            )
            for i in read_json("issues.json")
        ]
        return cls(
            branches=branches,
            pulls=pulls,
            issues=issues,
            suppressions=load_state_suppressions(state_dir / STATE_FILE),
        )


# Anyone can comment on a public repository; only these may give a dismissal its reason.
MAINTAINER_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}


def _maintainer_comment(comments: list[dict]) -> str:
    human = [
        c
        for c in comments
        if isinstance(c, dict)
        and c.get("authorAssociation") in MAINTAINER_ASSOCIATIONS
        and not str((c.get("author") or {}).get("login", "")).endswith("[bot]")
    ]
    if not human:
        return ""
    latest = max(human, key=lambda c: str(c.get("createdAt", "")))
    return " ".join(str(latest.get("body", "")).split())[:300]


def load_state_suppressions(path: Path) -> list[Suppression]:
    if not path.is_file():
        return []
    return parse_state_suppressions(path.read_text())


def parse_state_suppressions(text: str) -> list[Suppression]:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return []
    items = data.get("suppressions", []) if isinstance(data, dict) else []
    out = []
    for item in items:
        try:
            out.append(Suppression.model_validate(item))
        except ValueError:
            continue  # a broken entry must not block the pipeline; it simply does not apply
    return out


def dump_state_suppressions(items: list[Suppression]) -> str:
    payload = {"suppressions": [s.model_dump(mode="json", exclude_none=True) for s in items]}
    header = (
        "# Managed by secubot (false positives agreed by triage + adversarial review).\n"
        "# Entries expire and are then re-triaged. Delete an entry to force re-triage now.\n"
    )
    return header + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def suppression_matches(s: Suppression, cluster: Cluster) -> bool:
    if s.id and s.id not in {cluster.id, *cluster.fingerprints}:
        return False
    if s.rule:
        wanted = s.rule.strip().upper()
        ids = {x.upper() for x in [*cluster.rule_ids, *cluster.vuln_ids, *cluster.cwes]}
        if wanted not in ids:
            return False
    if s.path:
        spec = pathspec.PathSpec.from_lines("gitignore", [s.path])
        if not any(spec.match_file(p) for p in cluster.paths):
            return False
    return True


class Decision(BaseModel):
    cluster_id: str
    selected: bool
    reason: str
    group: str = ""
    """Stable key for the reason (see SKIP_GROUPS), used to summarise skipped clusters."""


# Why a cluster was not triaged, in the order the run summary lists them.
SKIP_GROUPS = {
    "cap": "Over the per-run limit (`policy.max_triage`), next run",
    "in_flight": "Already in progress (secfix branch, open PR or issue)",
    "cooldown": "Closed recently, cooling down (`policy.cooldown_days`)",
    "suppressed": "Suppressed (`.secfix.yml`, `secfix-state`, or issue closed as not planned)",
    "dependency": "Dependencies not taken (`policy.dependencies`, or no fixed version)",
    "protected": "CI/agent config (GitHub Actions…): report only, see Code Scanning. "
    "Hide with `paths.ignore_protected`",
    "unreachable": "Not reachable (govulncheck)",
    "severity": "Below `policy.min_severity`",
    "kind": "Kind not enabled (`policy.kinds`) or licence (report only)",
}


class Selection(BaseModel):
    selected: list[str]
    decisions: list[Decision]
    expired_suppressions: list[Suppression] = Field(default_factory=list)

    def reason_for(self, cluster_id: str) -> str:
        for d in self.decisions:
            if d.cluster_id == cluster_id:
                return d.reason
        return ""


def _dismissal(issues: list[IssueRef], ttl_days: int, today: dt.date) -> str | None:
    """Skip reason if a maintainer closed this cluster's issue as *not planned* recently.

    Only the latest dismissal counts; reopening the issue lifts it.
    """
    dismissed = [i for i in issues if i.dismissed and i.closed_at is not None]
    if not dismissed:
        return None
    latest = max(dismissed, key=lambda i: _utc(i.closed_at))
    until = _utc(latest.closed_at).date() + dt.timedelta(days=ttl_days)
    if until < today:
        return None  # expired: examine it again
    why = f": {latest.comment}" if latest.comment else ""
    return f"dismissed in issue #{latest.number} (closed as not planned) until {until}{why}"


def _utc(when: dt.datetime) -> dt.datetime:
    return when if when.tzinfo else when.replace(tzinfo=dt.UTC)


def _recent(when: dt.datetime | None, days: int, now: dt.datetime) -> bool:
    if when is None:
        return True
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.UTC)
    return now - when < dt.timedelta(days=days)


def _dependency_reason(c: Cluster, mode: str) -> str | None:
    """Return a skip reason, or None if the agent should take this dependency cluster."""
    if mode == "all":
        return None
    if mode == "none":
        return "dependency fixes disabled (policy.dependencies: none)"
    if c.key.endswith("|image"):
        return None  # base-image bumps are code changes in a Dockerfile; Renovate rarely helps
    if c.breaking_upgrade:
        return None
    if c.target_version is None and c.reachable == Reachability.YES:
        return None  # no fixed release but reachable: needs a code-level mitigation
    if c.target_version is None:
        return "no fixed version known and not proven reachable"
    return "non-breaking upgrade: left to Renovate/Dependabot (policy.dependencies)"


def select(
    report: ScanReport,
    state: RepoState,
    cfg: SecfixConfig,
    now: dt.datetime | None = None,
) -> Selection:
    now = now or dt.datetime.now(dt.UTC)
    today = now.date()
    policy = cfg.policy
    all_suppressions = [*cfg.suppressions, *state.suppressions]
    expired = [s for s in all_suppressions if not s.active(today)]
    active = [s for s in all_suppressions if s.active(today)]

    pulls_by_head: dict[str, list[PullRef]] = {}
    for p in state.pulls:
        pulls_by_head.setdefault(p.head, []).append(p)
    issues_by_id: dict[str, list[IssueRef]] = {}
    for i in state.issues:
        if i.cluster_id:
            issues_by_id.setdefault(i.cluster_id, []).append(i)

    protected = cfg.protected_spec()
    decisions: list[Decision] = []
    eligible: list[Cluster] = []
    for c in report.clusters:
        reason = None
        group = ""
        if c.paths and all(protected.match_file(p) for p in c.paths):
            # e.g. unpinned actions in .github/workflows: secubot may never edit these, so
            # triage would only spend money. They stay visible in Code Scanning.
            group = "protected"
            reason = "in a protected path (report only: secubot never edits CI/agent config)"
        elif c.kind not in policy.kinds:
            group = "kind"
            reason = f"kind '{c.kind.value}' not enabled (policy.kinds)"
        elif c.kind == Kind.LICENSE:
            group = "kind"
            reason = "licence findings are reported only"
        elif c.severity.rank < policy.min_severity.rank:
            group = "severity"
            reason = f"severity {c.severity.value} below policy.min_severity"
        elif hit := next((s for s in active if suppression_matches(s, c)), None):
            group = "suppressed"
            reason = f"suppressed until {hit.expires} ({hit.source}): {hit.reason}"
        elif dismissal := _dismissal(issues_by_id.get(c.id, []), policy.dismissed_ttl_days, today):
            group = "suppressed"
            reason = dismissal
        elif c.branch in state.branches:
            group = "in_flight"
            reason = f"branch {c.branch} already exists (in flight)"
        elif any(p.state == "OPEN" for p in pulls_by_head.get(c.branch, [])):
            group = "in_flight"
            reason = "open pull request"
        elif any(
            p.state == "CLOSED" and _recent(p.closed_at, policy.cooldown_days, now)
            for p in pulls_by_head.get(c.branch, [])
        ):
            group = "cooldown"
            reason = f"pull request closed without merge less than {policy.cooldown_days}d ago"
        elif any(i.state == "OPEN" for i in issues_by_id.get(c.id, [])):
            group = "in_flight"
            reason = "open issue"
        elif any(
            i.state == "CLOSED" and _recent(i.closed_at, policy.cooldown_days, now)
            for i in issues_by_id.get(c.id, [])
        ):
            group = "cooldown"
            reason = f"issue closed less than {policy.cooldown_days}d ago"
        elif (
            policy.skip_unreachable and c.kind == Kind.DEPENDENCY and c.reachable == Reachability.NO
        ):
            group = "unreachable"
            reason = "not reachable (govulncheck: vulnerable symbols are not called)"
        elif c.kind == Kind.DEPENDENCY:
            group = "dependency"
            reason = _dependency_reason(c, policy.dependencies)
        if reason:
            decisions.append(Decision(cluster_id=c.id, selected=False, reason=reason, group=group))
        else:
            eligible.append(c)

    def rank(c: Cluster) -> tuple:
        kind_order = {Kind.CODE: 0, Kind.DEPENDENCY: 1, Kind.IAC: 2, Kind.SECRET: 3}
        return (-c.severity.rank, -c.reachable.rank, kind_order.get(c.kind, 9), c.path, c.id)

    eligible.sort(key=rank)
    selected = eligible[: policy.max_triage]
    for c in selected:
        decisions.append(Decision(cluster_id=c.id, selected=True, reason="selected"))
    for c in eligible[policy.max_triage :]:
        decisions.append(
            Decision(
                cluster_id=c.id,
                selected=False,
                reason="over the per-run cap (max_triage)",
                group="cap",
            )
        )
    return Selection(
        selected=[c.id for c in selected], decisions=decisions, expired_suppressions=expired
    )


def branch_names(clusters: list[Cluster]) -> list[str]:
    return [f"{BRANCH_PREFIX}{c.id}" for c in clusters]
