# Security model

secubot runs a model with tool access over code it doesn't control, then turns the model's
output into branches and pull requests. The design assumes that **all repository content
and all scanner output is hostile**, and that the model can be manipulated. Every control
below is there so that a manipulated model can, at worst, produce a bad *draft* PR that a
human then rejects.

## Assets and adversaries

| Asset | Where it lives | Who would want it |
|---|---|---|
| `ANTHROPIC_API_KEY` | triage and fix jobs only (Claude Code process env) | anyone (spend, data) |
| Write access to the repository | publish job only (`GITHUB_TOKEN` or the App token) | anyone wanting to ship code |
| Ability to suppress findings | `.secfix.yml` (reviewed like code) and `secfix-state` (publish job) | someone hiding a vulnerability |
| Runner integrity | each job's ephemeral VM | supply-chain attackers |

Adversaries considered:

1. **Content injection.** Text in the repository or its dependencies (comments, docs, test
   fixtures, vendored code, package metadata) that ends up in front of the model, or a
   scanner rule message carrying instructions.
2. **A contributor who can merge to the default branch.** This person already has write
   access, so secubot must not give them more, for example a path to the API key or to
   suppressing findings without review.
3. **Compromised scanner or action release.** Mitigated by pinning (see below), not
   eliminated.

Out of scope: a compromised GitHub, Anthropic or runner host, and maintainers with admin
rights.

## Controls by layer

### Triggers and workflow

- **Triggers are `schedule` and `workflow_dispatch` only.** There is no `pull_request`,
  `pull_request_target`, `issue_comment` or any other event carrying attacker-supplied
  input. Dispatch needs write access. Runs always scan the default branch (or the
  dispatched ref) of the repository itself, never a fork.
- **Permissions start at `permissions: {}`.** Each job gets only what it needs (see the
  [job table](architecture.md#architecture)). The model runs only in jobs with
  `contents: read`, and the job holding write tokens runs no model and no repository code.
- **No cloud credentials anywhere.** The workflow defines no OIDC (`id-token`) permission
  and no cloud secrets. Don't add any to the caller.
- **Checkouts use `persist-credentials: false`,** except the publish job's single checkout
  that pushes.
- **Every action is pinned to a full commit SHA,** with the version in a comment. Dependabot
  updates them with a 7-day cooldown.
- **harden-runner** has a per-job egress allowlist and defaults to `block`. Triage only
  reaches `api.anthropic.com`, GitHub and PyPI (to install secubot). Publish and report have
  no Anthropic endpoint at all.
- **Job isolation.** Data passes between jobs only as artifacts, and publish treats those
  artifacts as untrusted: it re-validates every patch, re-checks branch state, and takes
  cluster ids only through a strict regex.

### Scanner supply chain

- Versions are pinned in `scanners/versions.env`. Trivy's download is checked against a
  sha256.
- semgrep, bandit and pip-audit are installed with `--require-hashes --no-deps` from locked
  requirement files into separate venvs. gosec and govulncheck are installed with `go
  install module@version`, verified against the Go checksum database.
- Scanners run with a scrubbed environment: no `ANTHROPIC_*`, `ACTIONS_*`, `CLAUDE_*`,
  `GITHUB_TOKEN` or `GH_TOKEN`.
  - pip-audit on fully pinned requirements runs with `--no-deps --disable-pip`, so it
    builds no packages.
  - semgrep runs with `--metrics=off` and trivy with `--disable-telemetry`.

### The agent (triage and fix)

| Control | Effect |
|---|---|
| `tools=[…]` (explicit list) | Only the listed tools exist in the session. Triage: Read/Grep/Glob. Fix: + Edit, + Bash if commands are configured |
| `disallowed_tools` | WebFetch, WebSearch, Task/Agent (sub-agents), NotebookEdit, Skill, SlashCommand, … |
| `permission_mode="dontAsk"` | anything not pre-approved is denied, never prompted |
| `--restricted` | file tools confined to the working directory; refuses `bypassPermissions`; settings, git and tool-config writes need the permission handler |
| `setting_sources=[]`, `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1` | the repository's `.claude/`, `CLAUDE.md`, hooks and settings are **not loaded**, so a repository can't reconfigure its own reviewer |
| `strict_mcp_config` + `mcp_servers={}` | no MCP servers, including a repository's `.mcp.json` |
| `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` (+ bubblewrap) | commands the agent runs don't inherit the API key or cloud credentials; the setup action installs `bwrap` |
| PreToolUse **gate** (`gate.py`) | deny-by-default re-check of every call: paths must be inside the repository and outside `.git/`, no edits to protected paths, Bash must match the allowlist exactly (`prefix:*` entries refuse shell metacharacters). Every decision is logged; denials are counted in the PR footer |
| `max_turns`, `max_budget_usd`, job `timeout-minutes` | bound cost and runtime per session |
| Telemetry, error reporting, auto-update off | no traffic besides the API |

### Prompt-injection handling

- **Data and instructions are separated.** The system prompt (`prompts/system.md`) states
  the trust boundary. Everything from scanners and the repository is placed inside
  `<untrusted>` tags. Before that, any `<untrusted>`/`</untrusted>` in the data is
  neutralised, so the data can't close the tag, and the data is length-limited.
- **Facts are passed as JSON.** The finding is given to the model as structured fields
  (ids, CWE, path, line, title), not as prose to follow.
- **Outputs are structured.** Every session answers in a JSON schema. Code makes the
  decisions (the reconcile table and patch validation), never free text.
- **Injection is reported, not obeyed.** Both triage passes and the fix agent can set
  `injection_suspected`. That forces an issue for a human and stops the fix.
- **Two-pass triage.** One pass that was fooled into "false positive" isn't enough to
  suppress a finding, because an independent adversarial pass has to agree. A
  suppression is also limited by severity and always expires.
- **Rendered output is sanitised.** Model and scanner text in PRs and issues gets
  `@`-mentions, `#123` / `GH-1` references, HTML, links, images and bidi controls
  neutralised, and code fences grow so the content can't break out. A manipulated model
  can't ping people, link phishing pages or close issues through keywords.

### The patch

`validate_patch` runs twice: in the fix job, and again in publish (which trusts nothing
from the fix artifact). It rejects:

- **Protected paths** that execute in CI or configure the agent or the pipeline:
  `.github/`, `.git*`, `.secfix.yml`, `.claude/`, `.mcp.json`, `CLAUDE.md`, `AGENTS.md`,
  `.devcontainer/`, `.vscode/`, `.pre-commit-config.yaml`, `CODEOWNERS`, … plus
  `fix.protected_paths`.
- **Sensitive paths** (auth, crypto, session, OAuth, JWT), unless the finding itself is
  located there.
- **Unusual file operations:** deletions, renames, binary changes, symlinks, submodules,
  mode changes (`+x`), and new files unless `fix.allow_new_files`.
- **Oversized diffs,** beyond `max_changed_files` / `max_changed_lines`.
- **Credentials:** known token formats (Anthropic, GitHub, AWS, Slack, private keys) and
  the literal values of the tokens present in the environment.

Publish applies the patch to the scanned commit with `git apply`, commits with
`core.hooksPath=/dev/null` and `--no-verify`, and opens a **draft** PR. Nothing merges
automatically. The repository's own branch protection, CODEOWNERS and CI still apply.
Use the GitHub App option so that CI actually runs on secubot PRs.

### Suppressions

There are two sources:

- `.secfix.yml` `suppressions:`, reviewed like code. Each entry needs a selector, a reason
  of at least 10 characters, and an expiry.
- Automatic suppressions from triage, written to the orphan branch `secfix-state`. Each one
  gets the TTL from `policy.suppression_ttl_days`, and only findings at or below
  `policy.auto_suppress_max_severity` are suppressed automatically.

Expired suppressions are listed in the run summary and dropped on the next state commit.
For stricter control, protect `secfix-state` with a ruleset that only the Actions bot or
the App may bypass.

## Residual risks

These are known gaps that are accepted or only partly mitigated. Review them before
rolling out to sensitive repositories.

1. **A plausible but wrong fix.** An injected or simply mistaken model can write a patch
   that passes build, test and rescan but changes behaviour or slips in a weakness. The
   size limits, sensitive and protected paths, and the draft-only PR reduce this. **Human
   review of the PR is the control that matters.** Treat secubot PRs like any external
   contribution.
2. **Fix-phase commands run repository code.** The `build`/`test` commands, and the code
   the agent just edited, run on the fix runner. They run with a scrubbed env, inside
   bubblewrap, with `contents: read`, behind the egress allowlist. The Claude Code process
   itself still holds `ANTHROPIC_API_KEY`, though.
   - Whether a sandboxed child can read the parent's `/proc/<pid>/environ` depends on the
     bubblewrap PID-namespace setup. This **has not been verified** on hosted runners.
   - Mitigations: egress `block` (exfiltration is limited to allowlisted hosts),
     `contents: read` tokens, the patch secret scan, and a **dedicated Anthropic workspace
     key with a spend limit**, rotated regularly.
   - If this matters to you, leave `commands.test` empty for untrusted repositories.
     Verification then relies on the rescan.
3. **Network inside the agent sandbox.** Whether `go get` / `uv lock` (dependency clusters)
   can reach the network from inside bubblewrap has **not been verified**. It fails safe:
   the fix fails and becomes an issue.
4. **Artifact tampering by a fix job.** Code running in a fix job could in principle
   upload a different `patch.diff` with the runner's artifact token. Publish's
   re-validation limits the damage to what a malicious agent could do anyway: a
   constrained draft PR.
5. **semgrep registry rules** (`p/default`) are fetched at run time, so they aren't pinned
   and results can change without a release. To make this deterministic, vendor the rules
   into the target repository or the central repository and reference them by path.
6. **"Allow GitHub Actions to create and approve pull requests"** applies to every workflow
   in the repository, not only secubot. Prefer the GitHub App, which doesn't need this
   setting.
7. **Cost amplification.** Someone who can merge code can trigger the maximum spend per
   run, but not more: `max_triage × 2 × triage_budget_usd + max_prs × fix_budget_usd`
   (defaults: 5 × 2 × $3 + 3 × $10 = $60). Lower the budgets for low-value repositories.
8. **Scanner coverage is the ceiling.** secubot only works on what the scanners report.
   Triage can dismiss a finding but never discovers new ones.

## Reporting

Treat findings in secubot itself like those in any internal security tool. The repository
runs its own pipeline on itself (`.github/workflows/secfix-self.yml`, egress `audit`).
