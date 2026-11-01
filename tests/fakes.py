"""A scripted stand-in for Claude Code sessions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from secubot.agent import SessionSpec, TurnResult

Step = Callable[[SessionSpec, str], TurnResult] | TurnResult | dict


@dataclass
class FakeFactory:
    """Each new session pops the next script; each turn pops the next step of it."""

    scripts: list[list[Step]]
    specs: list[SessionSpec] = field(default_factory=list)
    prompts: list[list[str]] = field(default_factory=list)
    closed: int = 0

    def __call__(self, spec: SessionSpec) -> FakeSession:
        self.specs.append(spec)
        self.prompts.append([])
        return FakeSession(self, spec, list(self.scripts.pop(0)), self.prompts[-1])


@dataclass
class FakeSession:
    factory: FakeFactory
    spec: SessionSpec
    steps: list[Step]
    prompts: list[str]

    async def turn(self, prompt: str) -> TurnResult:
        self.prompts.append(prompt)
        step = self.steps.pop(0)
        if callable(step):
            return step(self.spec, prompt)
        if isinstance(step, dict):
            return TurnResult(structured=step, cost_usd=0.5, num_turns=3)
        return step

    async def close(self) -> None:
        self.factory.closed += 1


def analysis(verdict="true_positive", **kw) -> dict:
    base = {
        "verdict": verdict,
        "reachable": "yes",
        "exploitable": "yes",
        "severity": "high",
        "confidence": "high",
        "reasoning": "argv flows into sh -c (goapp/main.go:19)",
        "evidence": [{"path": "goapp/main.go", "line": 31, "note": "os.Args[1] -> run()"}],
        "fix_strategy": "call the binary directly without a shell",
        "injection_suspected": False,
    }
    return {**base, **kw}


def challenge(holds=False, revised="true_positive", confidence="medium", **kw) -> dict:
    base = {
        "challenge_holds": holds,
        "revised_verdict": revised,
        "confidence": confidence,
        "arguments": "no sanitiser found",
        "evidence": [],
        "injection_suspected": False,
    }
    return {**base, **kw}
