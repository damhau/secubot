## Task: fix exactly one security finding

The finding below was triaged as a real problem (reasoning included). Change the code in
this repository so that the finding is resolved. A program will then build the project,
run the tests and re-run the scanner that reported it; a human will review the diff as a
draft pull request.

### Scope rules (a violation fails the run)

- Fix only this finding (all its listed locations). No unrelated refactors, renames,
  formatting changes, comment rewrites or dependency updates.
- Keep behaviour unchanged for legitimate inputs. Prefer the idiomatic secure API
  (e.g. `crypto/rand`, `exec.Command` with an argument list instead of a shell,
  `yaml.safe_load`, parameterised queries, a TLS config that verifies certificates).
- Do not modify tests to make them pass, and do not disable, skip or delete tests.
- Do not touch authentication, authorisation, session or cryptography code unless the
  finding itself is located there.
- Never change CI/workflow files, `.secfix.yml`, agent configuration, or lock files of
  unrelated packages. Do not add new dependencies, except the upgraded version of the
  vulnerable package itself.
- Keep the change small: at most {max_files} files and about {max_lines} changed lines.
{new_files_rule}
### Dependency upgrades

Upgrade the vulnerable package to the target version (or the lowest version that fixes
all listed vulnerabilities), update the manifest and lock file with the allowed commands,
and adapt the calling code to any breaking API change. If no fixed version exists,
mitigate in code (stop calling the vulnerable function, validate its input) and explain.

### Tools and verification

You can read and search the repository and edit files. You may run only these shell
commands, verbatim (or with arguments where a `:*` suffix is shown):

{commands}

Running the build and tests yourself before finishing is encouraged. Anything else is
blocked. When you are done, stop and answer with the JSON object required by the output
schema. If the finding cannot be fixed within these rules (for example it needs a design
change or a credential rotation), make no further edits and explain in `blocked_reason`.

{finding}

<untrusted>
### Triage reasoning (from an earlier read-only analysis; verify before relying on it)

{triage}
</untrusted>
