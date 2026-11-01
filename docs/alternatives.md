# Alternatives and complements

secubot does one specific job: on a schedule, it acts on the findings of **deterministic
scanners you already trust**, with a verified fix or an issue, inside your own CI and under
your own controls. Several products overlap with parts of that. Most of them are
complements rather than replacements. These notes were checked in November 2026; check
the linked pages for current scope and pricing.

## Summary

| Tool | Finds issues | Fixes | Runs | Good fit when |
|---|---|---|---|---|
| **secubot** | scanners (trivy, govulncheck, gosec, bandit, pip-audit, semgrep) | draft PR after build/test/rescan; otherwise an issue | your GitHub Actions, daily | you want scanner backlogs worked down automatically, with every control in your repository |
| **Claude Security** (managed, Enterprise plan) | Claude, multi-agent, hosted | yes | hosted, monitors connected repositories | you're on Enterprise and want vulnerabilities *beyond* what rule-based scanners see, without running CI for it |
| **Claude Security plugin** | Claude, multi-agent, in a session | patch files you apply yourself | developer's Claude Code session, on demand | periodic deep reviews of a repository or a branch diff by an engineer |
| `/security-review`, Code Review, security-guidance plugin | Claude | in-session / review comments | while writing code, on PRs | catching new issues before merge |
| **claude-code-action** | whatever you prompt | whatever you prompt | your GitHub Actions | building your own Claude workflows on the official action |
| **OpenHands Vulnerability Fixer** | Trivy, or uploaded scanner reports | PRs | self-hosted or OpenHands Cloud | you want an open-source, model-agnostic agent |
| **Copilot Autofix** / agentic autofix | CodeQL code scanning alerts | suggestions / draft PR (agentic) | GitHub | CodeQL is your main scanner and you have GitHub Code Security |
| **Dependabot / Renovate** | advisories in manifests | version bump PRs | GitHub / self-hosted | simple dependency upgrades (secubot defers to them) |

## Claude Security

- **Managed product** (Enterprise plan). A hosted service that monitors connected
  repositories and scans them with Claude, including Claude Mythos.
  - It *discovers* vulnerabilities by reasoning about the code. secubot never does that:
    triage can only confirm or dismiss what a scanner reported.
  - Choose it if you're on Enterprise and the gap you care about is logic and authorisation
    bugs that scanners don't express as rules.
  - It doesn't replace your scanners. Anthropic's own documentation places it alongside
    static analysis and dependency scanning.
- **Claude Security plugin** (`/plugin install claude-security@claude-plugins-official`).
  - It runs a multi-agent scan *inside a developer's Claude Code session*: architecture
    map, threat model, hunting, independent verification.
  - It writes a report (Markdown, JSONL and **SARIF**) and, on request, reviewed patch
    files. Patches are **never applied automatically**.
  - It is on-demand and interactive, not a scheduled pipeline, and scans are
    nondeterministic by design.
  - A good complement is to have an engineer run it quarterly on high-value repositories.
    Its SARIF can be uploaded to Code Scanning next to secubot's, and its patches go
    through normal review.
- **`/security-review`, Code Review and the security-guidance plugin** cover the moments
  before merge: one pass over a branch, multi-agent PR review on Team and Enterprise plans,
  and in-session guidance while Claude writes code. secubot covers the debt that is already
  on the default branch, so use both.

## claude-code-action

[`anthropics/claude-code-action`](https://github.com/anthropics/claude-code-action) is the
official GitHub Action for running Claude Code in workflows. secubot doesn't use it. It
drives Claude Code through the Claude Agent SDK instead, because it needs:

- an in-process **PreToolUse gate** (path and command policy, decisions logged and counted)
- **structured output** checked against a JSON schema at every stage
- a **multi-turn session** for the fix loop, so verification failures are fed back into the
  same context
- the per-session **cost and turn data** for the PR footer and the fleet report
- fine control of the hardening flags (`--restricted`, no setting sources, strict MCP, env
  scrub)

If you build on the action instead:

- **Use v1.0.74 or later.** Earlier versions read `.mcp.json` and `.claude/` from the
  checked-out PR head and enabled the project's MCP servers, which allowed code execution
  and secret theft from a malicious PR (CVE-2026-47751). The fix restores those files from
  the base branch.
- Pin it by full SHA. The current release at the time of writing is v1.0.266 at
  `18bb01f132748aac392d2992354fa598d28ada76`.
- Keep the same structure: no `pull_request_target`, no write tokens in the job that runs
  the model, an explicit tools allowlist, and egress limits.

## OpenHands Vulnerability Fixer

[OpenHands Vulnerability Fixer](https://github.com/OpenHands/vulnerability-fixer) is an
open-source (MIT) application released in March 2026. It runs Trivy on a repository, or
takes reports uploaded from other scanners, has an OpenHands agent fix the findings, and
opens pull requests for a human to review and merge. Scheduled scans are possible through
OpenHands Automations.

- **Choose it** if you need model choice beyond Claude or already run OpenHands.
- **Check before adopting:**
  - Where the agent runs and which token it holds while it runs.
  - Whether repository content can reconfigure the agent.
  - Whether fixes are verified by a rescan and your tests before a PR is opened.
  - Whether PRs are drafts.

  Measure it against the controls in [security.md](security.md).

## GitHub Copilot Autofix

- **Copilot Autofix** generates fix suggestions for **CodeQL** code scanning alerts. It is
  free on public repositories, and needs GitHub Code Security on private ones. Security
  campaigns can group up to 1,000 alerts for fix suggestions.
- **Agentic autofix** (generally available since October 2026, GitHub Enterprise Cloud
  with Code Security or Advanced Security):
  - Assign a default-branch alert, or up to 25 together, to Copilot.
  - Copilot plans a fix, validates it by **re-running CodeQL**, and opens a **draft PR**.
  - It consumes AI credits from the Code Security budget, plus Actions minutes.
  - Validation uses the default CodeQL query suite, so results from custom queries or
    other tools aren't confirmed. GitHub's documentation describes CodeQL alerts only.

**Choose it** if your code findings come from CodeQL and you have the licences. It is
deeply integrated and needs no pipeline of your own.

secubot fits better if your findings come from other scanners, mainly dependency and Go
reachability findings (govulncheck), semgrep, gosec and bandit. It also fits if you want
the triage step, with an adversarial second opinion and auto-suppression with expiry, and
a configuration you can audit and change. The two can run side by side. secubot uploads
under `secubot/<tool>` categories, so its alerts don't collide with CodeQL's.

## Building it yourself vs. secubot

A shorter version of this pipeline is a single job: scanner, then claude-code-action with
a "fix it" prompt, then create a PR. The parts that take the most work to get right are
what secubot provides:

- deterministic dedup and fingerprints that stay stable across line shifts
- state with no database: branches, PRs and issues on GitHub, plus a state branch
- the triage decision table
- the verification loop
- patch validation that runs twice
- job-level permission separation
- output sanitisation

## Sources

- [Claude Security plugin (Claude Code docs)](https://code.claude.com/docs/en/claude-security)
- [Claude Security product](https://claude.com/product/claude-security)
- [claude-code-action security advisory, CVE-2026-47751](https://releasealert.dev/cve/CVE-2026-47751)
- [OpenHands Vulnerability Fixer announcement](https://www.openhands.dev/blog/20260303-vulnerability-fixer), [docs](https://docs.openhands.dev/openhands/usage/use-cases/vulnerability-remediation)
- [Copilot Autofix for code scanning (GitHub Docs)](https://docs.github.com/en/code-security/concepts/code-scanning/autofix-for-code-scanning)
- [Agentic autofix GA (GitHub changelog, 2026-10-15)](https://github.blog/changelog/2026-10-15-agentic-autofix-for-code-scanning-alerts-general-availability)
- [Security campaigns GA (GitHub changelog, 2025-04-08)](https://github.blog/changelog/2025-04-08-security-campaigns-are-now-generally-available-to-help-address-security-debt-at-scale)
