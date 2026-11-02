"""Triage: read-only analysis, then an independent adversarial challenge, then a
deterministic reconciliation. The model never decides the action on its own: code maps
(analysis, challenge, policy) to fix / suppress / issue.

`policy.challenge: false` skips the challenge. The analysis verdict then stands alone, and
a false positive is suppressed only at high confidence.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from secubot import prompts
from secubot.agent import AgentFactory, SessionSpec, TurnResult
from secubot.config import SecfixConfig, Suppression
from secubot.gate import Gate, GatePolicy
from secubot.models import Cluster, Kind, Severity

Verdict = Literal["true_positive", "false_positive", "uncertain"]
YesNo = Literal["yes", "no", "unknown"]
Confidence = Literal["high", "medium", "low"]

_EVIDENCE = {
    "type": "array",
    "maxItems": 15,
    "items": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "line": {"type": "integer"},
            "note": {"type": "string"},
        },
        "required": ["path", "note"],
        "additionalProperties": False,
    },
}

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"enum": ["true_positive", "false_positive", "uncertain"]},
        "reachable": {"enum": ["yes", "no", "unknown"]},
        "exploitable": {"enum": ["yes", "no", "unknown"]},
        "severity": {"enum": [s.value for s in Severity]},
        "confidence": {"enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
        "evidence": _EVIDENCE,
        "fix_strategy": {"type": "string"},
        "injection_suspected": {"type": "boolean"},
    },
    "required": [
        "verdict",
        "reachable",
        "exploitable",
        "severity",
        "confidence",
        "reasoning",
        "evidence",
        "fix_strategy",
        "injection_suspected",
    ],
    "additionalProperties": False,
}

CHALLENGE_SCHEMA = {
    "type": "object",
    "properties": {
        "challenge_holds": {"type": "boolean"},
        "revised_verdict": {"enum": ["true_positive", "false_positive", "uncertain"]},
        "confidence": {"enum": ["high", "medium", "low"]},
        "arguments": {"type": "string"},
        "evidence": _EVIDENCE,
        "injection_suspected": {"type": "boolean"},
    },
    "required": [
        "challenge_holds",
        "revised_verdict",
        "confidence",
        "arguments",
        "evidence",
        "injection_suspected",
    ],
    "additionalProperties": False,
}


class Evidence(BaseModel):
    path: str
    line: int | None = None
    note: str


class Analysis(BaseModel):
    verdict: Verdict
    reachable: YesNo
    exploitable: YesNo
    severity: Severity
    confidence: Confidence
    reasoning: str = Field(max_length=20_000)
    evidence: list[Evidence] = Field(default_factory=list)
    fix_strategy: str = ""
    injection_suspected: bool = False


class Challenge(BaseModel):
    challenge_holds: bool
    revised_verdict: Verdict
    confidence: Confidence
    arguments: str = Field(max_length=20_000)
    evidence: list[Evidence] = Field(default_factory=list)
    injection_suspected: bool = False


Action = Literal["fix", "suppress", "issue", "error"]


class TriageResult(BaseModel):
    cluster_id: str
    action: Action
    final_verdict: Verdict | None = None
    reason: str
    analysis: Analysis | None = None
    challenge: Challenge | None = None
    cost_usd: float = 0.0
    error: str = ""
    suppression: Suppression | None = None
    denied_tool_calls: int = 0


def reconcile(
    cluster: Cluster, a: Analysis, c: Challenge | None, cfg: SecfixConfig
) -> tuple[Verdict, Action, str]:
    """Deterministic decision table. Errs towards a human when the two passes disagree.

    `c` is None when the challenge was skipped (`policy.challenge: false`).
    """
    if c is not None and c.challenge_holds and c.revised_verdict == a.verdict:
        c = c.model_copy(update={"challenge_holds": False})  # self-contradictory challenge

    if c is None:
        final: Verdict = a.verdict
        why = "single analysis pass (policy.challenge is off)"
    elif not c.challenge_holds:
        final = a.verdict
        why = "analysis upheld by adversarial review"
    elif c.revised_verdict == "true_positive" and c.confidence == "high":
        final = "true_positive"
        why = "adversarial review found a concrete exploitation path"
    else:
        final = "uncertain"
        why = "analysis and adversarial review disagree"

    if a.injection_suspected or (c is not None and c.injection_suspected):
        return final, "issue", "possible prompt injection in repository content; needs a human"

    if final == "true_positive":
        if cluster.kind == Kind.SECRET:
            return final, "issue", "hard-coded secret: rotate it, then remove it (human task)"
        return final, "fix", why
    if final == "false_positive":
        if not cfg.policy.auto_suppress:
            return final, "issue", f"{why}; auto-suppression disabled"
        if cluster.severity.rank > cfg.policy.auto_suppress_max_severity.rank:
            return (
                final,
                "issue",
                (
                    f"{why}, but scanner severity {cluster.severity.value} is above "
                    "policy.auto_suppress_max_severity: confirm before suppressing"
                ),
            )
        if c is None and a.confidence != "high":
            # No second opinion: one pass that was fooled must not hide a finding.
            return (
                final,
                "issue",
                f"{why}, at {a.confidence} confidence: confirm before suppressing",
            )
        return final, "suppress", why
    if (
        cfg.policy.bump_uncertain_dependencies
        and cluster.kind == Kind.DEPENDENCY
        and cluster.target_version
        and cluster.breaking_upgrade is False
    ):
        # Proving (un)reachability costs more than a verified minor/patch bump, and a
        # dependency bot would open this PR without any analysis.
        bump = f"non-breaking upgrade to {cluster.target_version} available, so fix anyway"
        return final, "fix", f"{why}; {bump}"
    return final, "issue", why


def _session(cfg: SecfixConfig, repo_root: Path, schema: dict) -> SessionSpec:
    gate = Gate(GatePolicy(root=repo_root, protected=cfg.protected_spec()))
    return SessionSpec(
        cwd=repo_root,
        model=cfg.models.triage,
        system_append=prompts.load("system"),
        gate=gate,
        output_schema=schema,
        max_turns=cfg.models.triage_max_turns,
        max_budget_usd=cfg.models.triage_budget_usd,
        effort=cfg.models.effort,
    )


async def _one_turn(factory: AgentFactory, spec: SessionSpec, prompt: str) -> TurnResult:
    session = factory(spec)
    try:
        return await session.turn(prompt)
    finally:
        await session.close()


def _denials(spec: SessionSpec) -> int:
    return sum(1 for e in spec.gate.log if not e["allowed"])


async def triage_cluster(
    cluster: Cluster,
    cfg: SecfixConfig,
    repo_root: Path,
    factory: AgentFactory,
    today: dt.date | None = None,
) -> TriageResult:
    today = today or dt.date.today()
    finding = prompts.finding_block(cluster)

    spec_a = _session(cfg, repo_root, ANALYSIS_SCHEMA)
    turn_a = await _one_turn(
        factory, spec_a, prompts.render(prompts.load("triage_analyse"), finding=finding)
    )
    cost = turn_a.cost_usd
    if turn_a.is_error or turn_a.structured is None:
        return TriageResult(
            cluster_id=cluster.id,
            action="error",
            reason="analysis session failed",
            error=turn_a.error or "no structured output",
            cost_usd=cost,
        )
    try:
        analysis = Analysis.model_validate(turn_a.structured)
    except ValueError as exc:
        return TriageResult(
            cluster_id=cluster.id,
            action="error",
            reason="invalid analysis",
            error=str(exc)[:500],
            cost_usd=cost,
        )

    challenge: Challenge | None = None
    denied = _denials(spec_a)
    if cfg.policy.challenge:
        # Fresh session: the challenger must not inherit the analyst's context or framing.
        spec_c = _session(cfg, repo_root, CHALLENGE_SCHEMA)
        analysis_text = prompts.neutralise(json.dumps(analysis.model_dump(mode="json"), indent=2))
        turn_c = await _one_turn(
            factory,
            spec_c,
            prompts.render(
                prompts.load("triage_challenge"), finding=finding, analysis=analysis_text
            ),
        )
        cost += turn_c.cost_usd
        denied += _denials(spec_c)
        if turn_c.is_error or turn_c.structured is None:
            return TriageResult(
                cluster_id=cluster.id,
                action="error",
                reason="challenge failed",
                error=turn_c.error or "no structured output",
                analysis=analysis,
                cost_usd=cost,
            )
        try:
            challenge = Challenge.model_validate(turn_c.structured)
        except ValueError as exc:
            return TriageResult(
                cluster_id=cluster.id,
                action="error",
                reason="invalid challenge",
                error=str(exc)[:500],
                analysis=analysis,
                cost_usd=cost,
            )

    final, action, why = reconcile(cluster, analysis, challenge, cfg)
    suppression = None
    if action == "suppress":
        passes = "" if challenge else ", single pass"
        suppression = Suppression(
            id=cluster.id,
            reason=f"secubot triage: false positive ({analysis.confidence} confidence{passes}). "
            + analysis.reasoning[:400],
            expires=today + dt.timedelta(days=cfg.policy.suppression_ttl_days),
            created=today,
            source="triage",
        )
    return TriageResult(
        cluster_id=cluster.id,
        action=action,
        final_verdict=final,
        reason=why,
        analysis=analysis,
        challenge=challenge,
        cost_usd=cost,
        suppression=suppression,
        denied_tool_calls=denied,
    )
