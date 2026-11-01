# Operations

## Releases

Target repositories call `damhau/secubot/.github/workflows/secfix.yml@v1`, or better, a
full commit SHA that Renovate/Dependabot keeps up to date (`@<sha> # v1.2.3`). The
reusable workflow checks secubot itself out at `secubot-ref`, so the default of that input
must point at the same release:

```bash
scripts/release.sh 1.2.0   # stamps secubot-ref: "v1.2.0", bumps pyproject, commits, tags v1.2.0, moves v1
git push origin HEAD v1.2.0 && git push -f origin v1
```

- **Patch or minor release.** Bug fixes, prompt tweaks and scanner bumps. Callers on `@v1`
  get them on the next run; callers pinned to a SHA get a PR.
- **Major release.** Anything that changes `.secfix.yml` incompatibly, the cluster id or
  fingerprint scheme (that would reopen every finding), or the permissions callers must
  grant.
- **Before tagging.** Run the self-scan (`secfix-self.yml`) and at least one real
  repository in `dry-run`. A prompt change is a behaviour change: compare a few triage
  results before and after.

## Scanner upgrades

Versions live in `scanners/versions.env`. The central repository's Dependabot covers
GitHub Actions and the Python lock file. For the scanners, use a Renovate custom manager:

```json
{
  "customManagers": [
    {
      "customType": "regex",
      "managerFilePatterns": ["/^scanners/versions\\.env$/"],
      "matchStrings": ["TRIVY_VERSION=(?<currentValue>\\S+)"],
      "depNameTemplate": "aquasecurity/trivy",
      "datasourceTemplate": "github-releases",
      "extractVersionTemplate": "^v(?<version>.+)$"
    },
    {
      "customType": "regex",
      "managerFilePatterns": ["/^scanners/versions\\.env$/"],
      "matchStrings": ["GOSEC_VERSION=(?<currentValue>\\S+)"],
      "depNameTemplate": "github.com/securego/gosec/v2",
      "datasourceTemplate": "go"
    },
    {
      "customType": "regex",
      "managerFilePatterns": ["/^scanners/versions\\.env$/"],
      "matchStrings": ["GOVULNCHECK_VERSION=(?<currentValue>\\S+)"],
      "depNameTemplate": "golang.org/x/vuln",
      "datasourceTemplate": "go"
    },
    {
      "customType": "regex",
      "managerFilePatterns": ["/^scanners/versions\\.env$/"],
      "matchStrings": ["SEMGREP_VERSION=(?<currentValue>\\S+)"],
      "depNameTemplate": "semgrep",
      "datasourceTemplate": "pypi"
    },
    {
      "customType": "regex",
      "managerFilePatterns": ["/^scanners/versions\\.env$/"],
      "matchStrings": ["BANDIT_VERSION=(?<currentValue>\\S+)"],
      "depNameTemplate": "bandit",
      "datasourceTemplate": "pypi"
    },
    {
      "customType": "regex",
      "managerFilePatterns": ["/^scanners/versions\\.env$/"],
      "matchStrings": ["PIP_AUDIT_VERSION=(?<currentValue>\\S+)"],
      "depNameTemplate": "pip-audit",
      "datasourceTemplate": "pypi"
    }
  ],
  "minimumReleaseAge": "7 days"
}
```

or bump the version by hand. Either way, regenerate the locks in the same PR:

```bash
scripts/lock-scanners.sh   # hash-locked requirements + trivy sha256 from the release checksums
```

A bump that skips this step fails safe: `install-scanners.sh` refuses a Trivy tarball
whose checksum doesn't match, and pip refuses unhashed requirements.

Scanner upgrades change results. New rules produce new clusters, and a changed message
doesn't change the fingerprint, which uses the CWE/CVE, path and line content. Ship them
as a minor release.

## Cost

Each agent session has a hard budget (`models.*_budget_usd`), and the number of sessions
per run is capped:

```
max per run = max_triage × 2 × triage_budget_usd + max_prs × fix_budget_usd
            = 5 × 2 × $3 + 3 × $10 = $60 with the defaults
```

Typical runs cost much less, because most days nothing new is selected: clusters already
in flight, suppressed, or handled earlier are skipped before any model call. A run with
nothing new costs only runner minutes. The actual cost is recorded:

- in every PR/issue footer: triage + fix cost of that cluster, and the number of denied
  tool calls
- in `run-report.json` (`cost_usd`, per cluster) and in the fleet dashboard

Ways to cut cost:

- Lower `max_triage` and `max_prs`.
- Use `effort: medium` for triage on low-value repositories.
- Raise `min_severity`.
- Let the control plane spread runs out.
- Keep a separate Anthropic workspace with a spend limit, so a misconfiguration can't run
  away.

## Day-to-day

| Situation | What to do |
|---|---|
| A secubot PR is wrong | Close it. The cluster rests for `cooldown_days` (90), then is triaged again. To stop it for good, add a suppression with a reason to `.secfix.yml` |
| A secubot issue is a false positive or an accepted risk | Close it as **Not planned**, with a comment saying why. The finding is suppressed for `dismissed_ttl_days` (180) and the comment is its recorded reason. Reopen the issue to undo it |
| Dependabot/Renovate and secubot opened PRs for the same upgrade | Possible for major upgrades only. Keep secubot's if it includes the code changes the upgrade needs, and close the other. If you merge the other one, secubot closes its own PR on the next run |
| A finding was fixed elsewhere (a merged Dependabot PR, a manual fix) | Nothing to do: the next run closes the secubot issue or PR (`policy.auto_close`) and lists it under *No longer reported*. Exceptions: issues for hard-coded secrets stay open until you close them after rotating the secret, and nothing is closed on a run where a scanner failed |
| Auto-close closed something it shouldn't have | The finding left the report: check for a `.secfix.yml` change (`paths.skip`, a scanner turned off) or a changed line that gave it a new id. Reopen the item if needed, and set `policy.auto_close: false` while you investigate |
| A secubot PR is right but incomplete | Push to the `secfix/<id>` branch like any PR, then mark it ready for review |
| An automatic suppression is wrong | Delete its entry from `suppressions.yml` on `secfix-state` (or delete the branch to reset all). Consider lowering `auto_suppress_max_severity` |
| A finding should be retried now | Delete the `secfix/<id>` branch and close its PR or issue. A closed PR or issue still triggers the cooldown, so also set `policy.cooldown_days: 0` for one run |
| An issue says "possible prompt injection" | Read the cited file. Text addressed to an AI or a reviewer in repository content is worth a look on its own |
| The same thing is flagged by two tools | It should already be one cluster. If it isn't, open an issue with both SARIF results; the fingerprint is `(kind, CWE/CVE, path, line content)` |

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| publish: `GitHub Actions is not permitted to create or approve pull requests` | Enable the repository setting, or configure the GitHub App ([onboarding](onboarding.md#3-github-app-for-publish-recommended)) |
| SARIF upload: `Advanced Security must be enabled` / `Code scanning is not enabled` | Private repository without GitHub Code Security: set `code-scanning: false` |
| `bwrap: setting up uid map: Permission denied` / `No permissions to create new namespace` | Unprivileged user namespaces are blocked. The setup action sets `kernel.apparmor_restrict_unprivileged_userns=0` on hosted Ubuntu runners. On self-hosted runners, install `bubblewrap` and `socat` and allow user namespaces |
| Fix result `blocked`: `Sandbox dependencies not available: socat not installed` | The agent's command sandbox needs `bubblewrap` and `socat`. The setup action installs both on hosted runners; on self-hosted runners, preinstall them |
| A step fails with a connection error under `egress-policy: block` | Look at the harden-runner insights for the blocked host. If the repository needs it (private registry, Go proxy), add it to your fork of the workflow. Use `audit` to find all of them at once |
| Triage result `error` | Usually the session budget or turn limit (`error_max_budget_usd` / `error_max_turns` in the triage artifact). Raise `triage_budget_usd` / `triage_max_turns`, or check the API key. Errors are retried on the next run |
| Every fix `failed` | Build/test don't work on a fresh runner. Set `commands.setup`, and check the fix job's logs and the `fix-<id>` artifact (attempt outputs) |
| Dependency fixes always fail | Possibly no network for `go get` / `uv lock` inside the agent sandbox (see [security](security.md#residual-risks)). These become issues, so handle them by hand or with Renovate |
| Nothing is ever selected | The run summary's *Not handled this run* table groups the skipped findings by reason (over the cap, in flight, cooldown, suppressed, dependency policy, CI config, severity) with examples. Every cluster's individual reason is in `selection.json` in the scan artifact |
| The summary lists many GitHub Actions findings | They are report-only, because secubot never edits workflows. Set `paths.ignore_protected: true` to drop them from secubot's report (Code Scanning keeps them), or fix them by pinning actions to a SHA |
| A scanner shows `failed` | The run continues without it. The detail is in the summary and the fleet dashboard. Pass `--strict` to `secubot scan` locally to fail fast |

## Running locally

The deterministic stages need no API key:

```bash
uv sync
export PATH="$PWD/.tools/bin:$PATH"
SECUBOT_TOOLS="$PWD/.tools" scripts/install-scanners.sh trivy-fs bandit pip-audit semgrep  # + gosec govulncheck (needs Go)
uv run secubot config-check --repo ../my-service
uv run secubot scan      --repo ../my-service --out out/scan/sarif
uv run secubot normalise --repo ../my-service --sarif-dir out/scan/sarif --out out/scan/report.json
uv run secubot select    --repo ../my-service --report out/scan/report.json --out out/scan/selection.json
uv run secubot summary   --scan-dir out/scan
```

`select` without `--state-dir` assumes no existing branches, PRs or suppressions.

Triage and fix need `ANTHROPIC_API_KEY` and run Claude Code against the checkout. **Run
them in a throwaway container or VM**, not on a workstation that holds credentials:

```bash
uv run secubot triage --repo ../my-service --scan-dir out/scan --out out/triage
uv run secubot fix    --repo ../my-service --scan-dir out/scan --triage-dir out/triage \
                      --cluster <id> --out out/fix/<id>
uv run secubot publish --repo ../my-service --scan-dir out/scan --triage-dir out/triage \
                       --fix-dir out/fix --out out/publish --dry-run
```

## Development

```bash
uv run pytest            # offline: SARIF fixtures, fake agent, local bare git remote
uv run ruff check src tests && uv run ruff format --check src tests
actionlint .github/workflows/*.yml examples/*/.github/workflows/*.yml
```

| Change | How to test it |
|---|---|
| a new scanner | add a SARIF fixture under `tests/fixtures/sarif/`, extend `prepare_sarif` and the counts in `test_normalise.py` |
| prompts | `tests/test_triage.py` covers the wiring. The behaviour needs a real dry run on a repository with known true and false positives |
| `validate_patch` / gate | `test_patch.py` / `test_gate.py`. Add the attack you are defending against as a test first |
