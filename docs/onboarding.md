# Onboarding

## Deployment model

The recommended setup is a **central repository plus a thin caller in each target
repository**.

| Lives in the central `secubot` repository | Lives in each target repository |
|---|---|
| reusable workflow (`workflow_call`), prompts, normaliser, gate, publisher | `.github/workflows/secfix.yml` (~10 lines) |
| pinned scanner versions and hash locks | optional `.secfix.yml` (commands, policy, suppressions) |
| release tags `vX.Y.Z` and the moving major tag `v1` | `ANTHROPIC_API_KEY` secret (repository, or org secret scoped to it) |
| optional control plane and fleet list | |

Why not the alternatives:

- **Copying the pipeline into every repository** means N places to patch when a prompt, a
  scanner pin or a security control changes.
- **A single central job that clones and pushes to every repository** needs a token that
  can write everywhere, and its blast radius is the whole organisation.

With the hybrid model, every run uses the target repository's own short-lived
`GITHUB_TOKEN`, logs stay in that repository, and upgrades roll out as one-line reviewed
PRs (`@v1` → a digest pin, via Renovate/Dependabot).

## 1. Set up the central repository (once)

1. Fork or copy this repository into your organisation, e.g. `YOUR_ORG/secubot`.
2. Replace `YOUR_ORG/secubot` in:
   - `.github/workflows/secfix.yml` (`secubot-repository` default)
   - `examples/`
   - `control-plane/fleet.yml`
3. Make the reusable workflow callable. Under **Settings → Actions → General → Access**,
   allow access from repositories in your organisation (for a private or internal
   repository). A public central repository needs nothing.
4. If the central repository is private, the jobs check secubot out with
   `SECUBOT_READ_TOKEN`. That is a fine-grained token, or better a GitHub App installation
   token, with **Contents: read on the central repository only**.
5. Cut the first release with `scripts/release.sh 0.1.0`, then push the tags (the script
   prints the commands). See [operations](operations.md#releases).

## 2. Onboard a repository

### Secrets

| Secret | Required | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | yes | Use a **dedicated Anthropic workspace** for secubot with a monthly spend limit. Store it as an org secret limited to the onboarded repositories |
| `SECUBOT_READ_TOKEN` | if the central repo is private | see above |
| `SECUBOT_APP_ID`, `SECUBOT_APP_PRIVATE_KEY` | recommended | GitHub App used by publish (below) |

The caller has to pass secrets explicitly. Don't use `secrets: inherit`, because the
reusable workflow should only receive what it needs.

### Repository settings

- **PR creation.**
  - With the App: nothing to do.
  - Without the App: enable **Settings → Actions → General → Workflow permissions → Allow
    GitHub Actions to create and approve pull requests**. Without this, publish fails on
    `gh pr create`. The setting applies to every workflow in the repository; that is why
    the App is preferred.
- **Labels.** Publish creates `security` (and any `labels:` from `.secfix.yml`) if they
  don't exist.
- **Code Scanning.** SARIF upload works on public repositories. On private repositories it
  needs **GitHub Code Security** (GHAS). Without it, set `code-scanning: false`. The rest of
  the pipeline doesn't depend on Code Scanning.
- **Branch protection.**
  - Keep your normal rules on the default branch. secubot only opens draft PRs.
  - Optionally add a ruleset that allows only the Actions bot or the App to create or
    update `secfix/*` and `secfix-state`.

### The caller workflow

Copy [`examples/target-repo/.github/workflows/secfix.yml`](../examples/target-repo/.github/workflows/secfix.yml)
and pick a different cron minute and hour for each repository (or use the control plane).
The caller's `permissions:` block is the **ceiling**: each job in the reusable workflow
narrows it further. For the first run, add this:

```yaml
    with:
      dry-run: true # scan, triage, fix; publish nothing
      egress-policy: audit # harden-runner records connections instead of blocking
```

Run it with **Actions → secfix → Run workflow** and check:

1. The **run summary** (on the run page): scanner status, then *Handled this run* with each
   triaged finding's verdict and outcome (the reasoning is under *Triage reasoning*).
2. *Not handled this run*: everything left alone, grouped by reason. Add `paths.skip` and
   `suppressions` for noise, and `paths.ignore_protected: true` if the GitHub Actions
   findings are just clutter for you.
3. The **fix jobs**: whether build/test work in CI. Set `commands.setup` if dependencies
   must be fetched first (e.g. `go mod download`, `uv sync --frozen`).
4. The **harden-runner** insights for each job: any endpoint the repository legitimately
   needs (a private module proxy, a package mirror). Add it in your fork of the workflow
   or ask for an input, then switch back to `block`.

Then remove `dry-run` and `egress-policy`. Keep `policy.max_prs: 1` for the first weeks if
you want a slow start.

### `.secfix.yml`

Start from the [annotated example](../examples/target-repo/.secfix.yml); every key is
optional. The useful minimum:

```yaml
commands:
  setup: go mod download
  build: go build ./...
  test: go test ./...
paths:
  skip: [vendor/, "**/testdata/", docs/]
```

Validate it locally with `uvx --from git+https://github.com/YOUR_ORG/secubot secubot
config-check --repo .`, or with `uv run secubot config-check --repo <path>` from a
checkout. The full reference is in [configuration](configuration.md).

### Dependabot / Renovate

secubot is designed to run next to one of them. With the default
`policy.dependencies: breaking-only`, the work is split like this:

| Finding | Handled by |
|---|---|
| Vulnerable dependency with a minor or patch fix | **Dependabot/Renovate.** secubot drops it before triage, so it costs nothing |
| Vulnerable dependency whose fix is a major (or 0.x minor) upgrade | **secubot.** The agent also changes the code the upgrade breaks, and the fix is verified by build, test and rescan |
| Vulnerable code that is reachable but has no fixed release | **secubot**, as a code-level mitigation or an issue |
| Code, Dockerfile, IaC and secret findings | **secubot** |
| Routine version updates, GitHub Actions, base images | **Dependabot/Renovate** |

`policy.bump_uncertain_dependencies` only matters with `dependencies: all`, because with
`breaking-only` those findings never reach triage. Use `dependencies: all` only on a
repository that has neither tool. Remove it in the same commit that turns one on, or the
two open PRs for the same bumps.

**Enable Dependabot.** Security updates (alerts and fix PRs) are repository settings:

```bash
gh api -X PUT repos/OWNER/REPO/vulnerability-alerts
gh api -X PUT repos/OWNER/REPO/automated-security-fixes
```

Version updates need a `.github/dependabot.yml` with one entry per manifest directory.
Start from [`examples/target-repo/.github/dependabot.yml`](../examples/target-repo/.github/dependabot.yml)
(Go, uv, npm, Docker, GitHub Actions) or
[`renovate.json`](../examples/target-repo/renovate.json). The `github-actions` entry (or
Renovate's digest pinning) also keeps the `uses: …/secfix.yml@…` pin current once it
points at a release, so secubot upgrades arrive as reviewed PRs. A pin on a branch such
as `@main` has nothing to bump.

**How they interact:**

- Dependabot and Renovate PRs don't trigger secubot: the caller workflow runs only on its
  schedule or by hand. secubot scans the default branch, so a finding stays reported
  until the bump is merged.
- **The same major upgrade can get two PRs.** secubot only checks its own `secfix/*`
  branches, not Dependabot's. secubot's PR is usually the one to keep, because it includes
  the code changes and passed your tests. If you merge Dependabot's instead, secubot closes
  its own PR on the next run.
- **secubot cleans up after Dependabot.** When a merged Dependabot PR (or a manual fix)
  resolves a finding that has an open secubot issue or PR, the next run closes it with a
  comment (`policy.auto_close`). Issues for hard-coded secrets are the exception: close
  those yourself once the secret is rotated.
- Suppressions don't cross over. A secubot suppression or dismissal doesn't dismiss the
  Dependabot alert, and a dismissed Dependabot alert doesn't suppress the finding in
  secubot. For dependencies this rarely matters, because the bump is the fix either way.

## 3. GitHub App for publish (recommended)

PRs opened with `GITHUB_TOKEN` don't trigger `pull_request` workflows, so the repository's
CI would never run on them. A GitHub App fixes that and removes the need for the
"Actions may create PRs" setting.

1. Create an App (org settings → Developer settings → GitHub Apps). No webhook, no
   callback URL.
2. Give it these **repository permissions**:
   - Contents: read & write
   - Pull requests: read & write
   - Issues: read & write
   - Metadata: read

   Grant nothing else, and in particular **not** Workflows. Patches can never touch
   `.github/`, so it isn't needed, and without it a token leak can't change CI.
3. Install it only on the onboarded repositories.
4. Store `SECUBOT_APP_ID` and `SECUBOT_APP_PRIVATE_KEY` as org secrets scoped to those
   repositories, and pass them in the caller:

```yaml
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      SECUBOT_APP_ID: ${{ secrets.SECUBOT_APP_ID }}
      SECUBOT_APP_PRIVATE_KEY: ${{ secrets.SECUBOT_APP_PRIVATE_KEY }}
```

The publish job mints a token scoped to the current repository with exactly those three
permissions, and commits under the App's bot identity.

## Variants

### Monorepo

Run the reusable workflow once per component, each run with its own config:

- skip patterns that carve out the component
- the component's own build and test commands
- its own PR budget

See [`examples/monorepo/`](../examples/monorepo/).

- `instance: -<name>` namespaces the artifacts (`secubot-api-scan`, …), so several calls
  can run in one workflow run.
- Cluster ids include the path, so branches and issues of different components never
  collide.
- Auto-close is scoped by instance. Every issue and PR body records the `instance` that
  opened it, and a run only closes its own. Items opened before secubot recorded the
  instance belong to the run without an `instance`.
- Carve out a component with negated skip patterns
  ([`services-api.secfix.yml`](../examples/monorepo/services-api.secfix.yml)):

  ```yaml
  paths:
    skip: ["/*", "!/services/", "/services/*", "!/services/api/"]
  ```

- Keep `max-parallel: 1` on the matrix to flatten spend. Publish is serialised per
  repository either way.
- Set `code-scanning: false` on the component runs, and upload SARIF from a single
  full-repository run (or a separate CodeQL/Code Scanning setup). Several uploads with the
  same category would overwrite each other.

### Cross-organisation

A reusable workflow can only be called from repositories that can see it:

| Central repository | Callable from |
|---|---|
| public | anywhere |
| internal (Enterprise) | every organisation in the enterprise, with access enabled in its Actions settings |
| private | its own organisation, with access enabled |

For organisations that can't see it (separate enterprises, customer orgs):

1. **Mirror per organisation (recommended).** Keep a read-only `OTHER_ORG/secubot` mirror
   that a scheduled job updates from the source's release tags only. Callers in that org
   use `OTHER_ORG/secubot/.github/workflows/secfix.yml@v1`. Each organisation keeps its own
   Anthropic workspace and key, its own App, and its own control plane. Nothing crosses
   the boundary at run time.
2. **Public central repository.** If the code and prompts can be public, this is the
   simplest option. The repository holds no secrets; everything sensitive stays in the
   callers.

Avoid a central job holding tokens for several organisations. That is exactly the blast
radius the hybrid model is meant to avoid.

## Control plane (optional)

When you have many repositories, the control plane in the central repository
(`.github/workflows/control-plane.yml`):

- **dispatches** each repository's caller workflow in its own hourly slot, using
  `sha256(repo) mod slots`. API spend and runner usage spread over the day, and you can
  then remove the `schedule:` trigger from the callers (keep `workflow_dispatch`).
- **collects** the latest `secubot*-report` artifact from each repository into a dashboard
  artifact (`dashboard.md`, `fleet.json`). The dashboard shows severity counts, PRs and
  issues opened, cost, and failed scanners.

Setup:

1. Create a second, separate GitHub App ("secubot dispatch") with **Actions: read &
   write** and Metadata: read only. Install it on the fleet's repositories.
2. Add the `SECUBOT_DISPATCH_APP_ID` and `SECUBOT_DISPATCH_APP_PRIVATE_KEY` secrets to the
   central repository.
3. List the repositories in [`control-plane/fleet.yml`](../control-plane/fleet.yml). Each
   entry can override `ref`, the `workflow` file and `inputs` (e.g. `dry-run: "true"`
   while onboarding), or set `enabled: false`.
4. Dispatch one repository by hand with **Run workflow → action: dispatch, repo:
   org/name**.

The control plane never holds the Anthropic key, never checks out target code and can't
write code. Its token can only start workflows that already exist in the target
repositories and read their artifacts.
