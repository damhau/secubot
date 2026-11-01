# Configuration

## Reusable workflow

```yaml
jobs:
  secfix:
    uses: YOUR_ORG/secubot/.github/workflows/secfix.yml@v1
    permissions: { contents: write, pull-requests: write, issues: write, security-events: write, actions: read }
    with: { … } # all optional
    secrets: { ANTHROPIC_API_KEY: …, … }
```

### Inputs

| Input | Default | Description |
|---|---|---|
| `config-path` | `.secfix.yml` | configuration file in the target repository |
| `dry-run` | `false` | scan, triage and fix, but push nothing and open no PRs, issues or suppressions |
| `code-scanning` | `true` | upload each scanner's SARIF to Code Scanning (category `secubot/<tool>`). Needs GitHub Code Security on private repositories |
| `egress-policy` | `block` | harden-runner policy. Use `audit` while onboarding |
| `runs-on` | `ubuntu-24.04` | runner label. The agent sandbox setup assumes Ubuntu (apt, AppArmor sysctl) |
| `go-version-file` | `go.mod` | used by `setup-go` when Go is detected |
| `max-parallel-fixes` | `2` | concurrent fix jobs |
| `instance` | `""` | artifact namespace for several calls in one run (monorepo), e.g. `-api` |
| `secubot-repository` | `YOUR_ORG/secubot` | central repository to check secubot out from |
| `secubot-ref` | the release tag | ref of the central repository. Stamped by `release.sh` so `@v1` runs matching code. Override only for testing |

### Secrets

| Secret | Required | Used by |
|---|---|---|
| `ANTHROPIC_API_KEY` | yes | triage, fix |
| `SECUBOT_READ_TOKEN` | if the central repository is private | every job (checkout of secubot) |
| `SECUBOT_APP_ID` / `SECUBOT_APP_PRIVATE_KEY` | no | publish (PRs that trigger CI) |

### Caller permissions

The caller's `permissions:` is the ceiling for the whole called workflow, and each job
narrows it further:

- `contents: write`: publish pushes `secfix/*` and `secfix-state`
- `pull-requests: write`, `issues: write`: publish
- `security-events: write`: SARIF upload
- `actions: read`: SARIF upload on private repositories

With `code-scanning: false` you can drop `security-events` and `actions`.

## `.secfix.yml`

Every key is optional. Unknown keys are **errors**, so typos don't silently do nothing.
Check a file with `secubot config-check --repo <path>`, which prints the effective
configuration and the detected languages. There is an annotated full example at
[`examples/target-repo/.secfix.yml`](../examples/target-repo/.secfix.yml).

### Top level

| Key | Default | |
|---|---|---|
| `version` | `1` | |
| `languages` | auto | `[go, python]`. Detected from `go.mod`, `pyproject.toml`, `setup.py`, `setup.cfg`, `uv.lock` and `requirements*.txt` outside skipped paths |
| `labels` | `[security]` | labels on PRs and issues (created if missing) |

### `paths`

| Key | Default | |
|---|---|---|
| `skip` | `.git/`, `vendor/`, `node_modules/`, `third_party/`, `.venv/`, `venv/`, `**/testdata/` | gitignore-style patterns, relative to the repository root. Findings under them are dropped. Literal directory prefixes (`vendor/`) are also passed to the scanners as excludes. Negation (`!`) works, which is how a monorepo component is carved out |
| `ignore_protected` | `false` | drop findings in protected paths (GitHub Actions workflows, agent and editor config) from secubot's report. secubot never edits those files, so they are report-only anyway. They are still scanned and still uploaded to Code Scanning, so the Security tab keeps them |

Setting `skip` **replaces** the defaults, so repeat the defaults you want to keep. To keep
GitHub Actions findings out of Code Scanning as well, add `.github/` to `skip` instead.

### `commands`

These are shell commands, run by secubot **with a scrubbed environment** (no Anthropic or
GitHub tokens) from the repository root.

| Key | Default | |
|---|---|---|
| `setup` | none | runs once before the fix agent starts (`go mod download`, `uv sync --frozen`). If it fails, the fix is an `error` and is retried on the next run |
| `build` | none | verification step 1 |
| `test` | none | verification step 2 |
| `timeout_minutes` | `20` | per command |

The fix agent may run `build` and `test` itself, but **only verbatim**: the gate compares
the whole command string. Keep them simple and wrap anything complex in a make target or a
script. Without `build` and `test`, a fix is verified only by the rescan, and the PR says
so.

### `scanners`

| Key | Default | |
|---|---|---|
| `trivy` | `true` | trivy fs: dependencies, IaC, secrets |
| `trivy_image.enabled` | `false` | `docker build` + image scan |
| `trivy_image.dockerfile` / `.context` | `Dockerfile` / `.` | |
| `govulncheck` | `true` | Go: vulnerabilities with reachability |
| `gosec` | `true` | Go: code |
| `bandit` | `true` | Python: code |
| `pip_audit` | `true` | Python: dependencies (`uv.lock` or `requirements*.txt`) |
| `semgrep.enabled` | `true` | |
| `semgrep.configs` | `[p/default]` | registry packs, or rule files relative to the repository |

Go scanners run only when Go is detected, Python scanners only when Python is.

### `policy`

| Key | Default | |
|---|---|---|
| `min_severity` | `medium` | `info`, `low`, `medium`, `high`, `critical` |
| `max_triage` | `5` | clusters triaged per run (2 agent sessions each) |
| `max_prs` | `3` | fix jobs / draft PRs per run. Extra true positives are deferred to the next run |
| `kinds` | `[code, dependency, iac, secret]` | `license` findings are reported but never acted on |
| `skip_unreachable` | `true` | drop Go dependency findings that govulncheck proved are not called |
| `dependencies` | `breaking-only` | `all`, `breaking-only`, or `none`. `breaking-only` leaves non-breaking upgrades to Renovate/Dependabot. It takes upgrades across a major version (or a 0.x minor), and reachable vulnerabilities without a fixed version |
| `bump_uncertain_dependencies` | `true` | when triage ends `uncertain` on a dependency with a fixed version and the upgrade is non-breaking, attempt the bump anyway (draft PR, verified by build/test/rescan). Major (breaking) upgrades and findings without a fixed version still become issues |
| `auto_suppress` | `true` | record agreed false positives on `secfix-state` |
| `auto_suppress_max_severity` | `high` | above this, an agreed false positive becomes an issue for a human to confirm |
| `suppression_ttl_days` | `30` | lifetime of automatic suppressions |
| `cooldown_days` | `90` | after a secubot PR is closed unmerged, or its issue is closed, leave the cluster alone this long |
| `auto_close` | `true` | close secubot's open issues and PRs whose finding a run no longer reports (fixed by a Dependabot PR or by hand, or now excluded), with a comment. Only when every scanner succeeded. A PR's `secfix/<id>` branch is deleted too. Issues for hard-coded secrets are never closed automatically |
| `dismissed_ttl_days` | `180` | closing a secubot issue as **Not planned** (false positive, accepted risk) suppresses the finding this long, counted from the close date. The latest comment by a maintainer is recorded as the reason. Reopen the issue to undo it |

### `fix`

| Key | Default | |
|---|---|---|
| `max_attempts` | `3` | 1–5 agent turns per cluster, each followed by verification |
| `extra_commands` | `[]` | additional Bash commands for the agent: exact strings, or `prefix:*` (prefix match, no shell metacharacters), e.g. `["make lint", "go vet:*"]` |
| `allow_new_files` | `false` | enable the Write tool and allow added files in the patch |
| `sensitive_paths` | auth / authn / authz / crypto / security / session / oauth / jwt globs | may only change if the finding itself is located there. Setting it replaces the defaults |
| `protected_paths` | `[]` | **added to** the built-in list, which can't be removed: `.git/`, `.github/`, `.gitmodules`, `.gitattributes`, `.secfix.yml`, `.secfix/`, `.claude/`, `.mcp.json`, `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.devcontainer/`, `.vscode/`, `.idea/`, `.pre-commit-config.yaml`, `.gitlab-ci.yml`, `CODEOWNERS` |
| `max_changed_files` | `10` | |
| `max_changed_lines` | `400` | added + removed |

For dependency clusters, the agent can also run `go get:*` and `go mod tidy` (Go) or
`uv lock:*` (Python).

### `models`

| Key | Default | |
|---|---|---|
| `triage` | `claude-opus-5-5` | model for both triage passes |
| `fix` | `claude-opus-5-5` | |
| `effort` | `high` | `low`, `medium`, `high`, `xhigh`, `max` |
| `triage_budget_usd` | `3` | hard cap **per session** (a cluster's triage is two sessions) |
| `fix_budget_usd` | `10` | hard cap per fix session (all attempts share it) |
| `triage_max_turns` / `fix_max_turns` | `40` / `60` | |

### `suppressions`

These are human-reviewed exceptions. Each one needs at least one selector, a reason of at
least 10 characters, and an expiry date. For a single finding that secubot raised as an
issue, closing the issue as **Not planned** is quicker (`policy.dismissed_ttl_days`); use
this list for exceptions that cover a rule or a directory, or that should go through review.

```yaml
suppressions:
  - rule: G404 # rule id, CVE/GHSA/GO id, or CWE (e.g. CWE-338)
    path: internal/sim/** # gitignore-style, matched against the cluster's paths
    reason: math/rand is used for simulation jitter, never for secrets
    expires: 2027-06-30
  - id: 3304d9e96d63 # a cluster id (from the summary / branch name) or a finding fingerprint
    reason: accepted risk, see SEC-142; vendor upgrade scheduled for Q1
    expires: 2027-03-31
```

All the selectors given must match. Expired entries are ignored and listed in the run
summary, so they are re-examined. Automatic suppressions from triage are stored separately
in `suppressions.yml` on the `secfix-state` branch (same format, `source: triage`).
To undo one early, delete the entry there, or delete the branch to reset them all.

## CLI

Each workflow step is a `secubot` subcommand. `secubot <cmd> --help` lists the options.

| Command | Purpose |
|---|---|
| `config-check` | validate `.secfix.yml`, print the effective config and the detected languages |
| `detect` | languages, Go modules, enabled tools (`--github-output`) |
| `scan` | run the enabled (or `--tools`) scanners, write SARIF and `status.json` |
| `normalise` | SARIF → `report.json` (findings and clusters) |
| `select` | apply state, policy and suppressions → `selection.json` |
| `triage` | two-pass triage of the selected clusters → `triage.json`, fix matrix |
| `fix` | fix one cluster → `result.json`, `patch.diff` |
| `recheck` | used by the agent during a fix: rescan the cluster's tools and report whether it is resolved |
| `publish` | branches, PRs, issues and state commits (`--dry-run`) |
| `summary` | job summary markdown + `run-report.json` |
| `pip-audit-sarif` | convert a pip-audit JSON report to SARIF |
| `fleet-dispatch`, `fleet-report` | control plane |
