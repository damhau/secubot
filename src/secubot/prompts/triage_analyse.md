## Task: triage one security finding (read-only)

A deterministic scanner pipeline reported the finding below. Several tools may have
reported the same issue; they have been merged. Your job is to decide, by reading the
code, whether this is a real, exploitable problem in this repository and how severe it
really is. You cannot modify anything.

Work through these questions in order:

1. **Reachability.** Is the flagged code (or, for a dependency, the vulnerable function of
   the package) actually reached from a production entry point — an HTTP handler, CLI
   command, message consumer, scheduled job, exported library API? Use Grep/Glob to trace
   callers. Code that is only reached from tests, examples, dead code or build tooling is
   not reachable in production. If a call path is given by the scanner, verify it.
2. **Exploitability.** Can an attacker control the input that reaches the sink? Look for
   validation, sanitisation, allow-lists, constant arguments, framework protections, and
   deployment context (e.g. a CLI only run by operators). For dependencies, check whether
   the vulnerable feature or configuration is actually used.
3. **Real severity.** Given reachability and exploitability, what severity would a careful
   security engineer assign? It may be lower or higher than the scanner's.
4. **Fix strategy.** If it is real: the smallest change that removes the vulnerability
   without changing intended behaviour (or the target version for an upgrade, and what
   code must change for breaking APIs).

Verdict meanings:
- `true_positive`: the weakness is present and plausibly exploitable or reachable in production.
- `false_positive`: the scanner is wrong, or the code is unreachable/unexploitable in practice.
- `uncertain`: you could not establish either with reasonable confidence.

Prefer `uncertain` over a confident guess. A wrong `false_positive` hides a real
vulnerability for weeks; a wrong `true_positive` costs one reviewed draft PR.

{finding}

Answer with the JSON object required by the output schema.
