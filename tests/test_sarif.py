from __future__ import annotations

import json

from conftest import PROJECT, SARIF, prepare_sarif

from secubot.models import Kind, Reachability, Severity
from secubot.sarif import (
    go_module_for,
    line_anchor,
    merge_runs,
    normalise_package,
    parse_sarif,
    primary_vuln_id,
    rewrite_uris,
    vuln_ids_in,
)


def _parse(tmp_path, name, project):
    files = {f.stem: f for f in prepare_sarif(project, tmp_path / "s")}
    return parse_sarif(files[name], project)


def test_ids_and_package_names():
    text = "CVE-2022-32149 GHSA-69ch-w2m2-3vjp GO-2022-1059 PYSEC-2018-28 CVE-2022-32149"
    assert vuln_ids_in(text) == [
        "CVE-2022-32149",
        "GHSA-69ch-w2m2-3vjp",
        "GO-2022-1059",
        "PYSEC-2018-28",
    ]
    assert primary_vuln_id(["GO-2022-1059", "GHSA-69ch-w2m2-3vjp", "CVE-2022-32149"]) == (
        "CVE-2022-32149"
    )
    assert normalise_package("PyYAML") == "pyyaml"
    assert normalise_package("Foo_Bar.baz") == "foo-bar-baz"
    assert normalise_package("golang.org/x/text") == "golang.org/x/text"


def test_go_module_for():
    gomod = (PROJECT / "goapp" / "go.mod").read_text()
    assert go_module_for("golang.org/x/text/language", gomod) == "golang.org/x/text"
    assert go_module_for("net/http", gomod) == "stdlib"


def test_line_anchor_ignores_whitespace():
    assert line_anchor("  x := 1 ") == line_anchor("x  :=  1")
    assert line_anchor("a") != line_anchor("b")


def test_rewrite_uris_makes_paths_repo_relative(project):
    doc = json.loads(
        (SARIF / "gosec.sarif").read_text().replace("file:///work/", project.as_uri() + "/")
    )
    doc = rewrite_uris(doc, project, prefix="goapp")
    uris = {
        loc["physicalLocation"]["artifactLocation"]["uri"]
        for run in doc["runs"]
        for r in run["results"]
        for loc in r["locations"]
    }
    assert uris == {"goapp/main.go"}
    assert all("originalUriBaseIds" not in run for run in doc["runs"])


def test_merge_runs_keeps_one_run():
    a = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "gosec", "rules": [{"id": "G1"}]}},
                "results": [{"ruleId": "G1", "ruleIndex": 0}],
            }
        ],
    }
    b = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "gosec", "rules": [{"id": "G1"}, {"id": "G2"}]}},
                "results": [{"ruleId": "G2", "ruleIndex": 1}],
            }
        ],
    }
    merged = merge_runs([a, b])
    assert len(merged["runs"]) == 1
    run = merged["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["G1", "G2"]
    assert len(run["results"]) == 2
    assert all("ruleIndex" not in r for r in run["results"])


def test_govulncheck_reachability_and_module(tmp_path, project):
    findings = _parse(tmp_path, "govulncheck", project)
    text = [f for f in findings if f.package == "golang.org/x/text"]
    assert text, "x/text finding expected"
    called = [f for f in text if f.reachable == Reachability.YES]
    assert called and all(f.severity == Severity.HIGH for f in called)
    assert called[0].installed_version in {"v0.3.7", "0.3.7"}
    assert called[0].call_path, "call stack from codeFlows expected"
    stdlib = [f for f in findings if f.package == "stdlib"]
    assert stdlib and all(f.reachable == Reachability.NO for f in stdlib)
    assert all(f.kind == Kind.DEPENDENCY for f in findings)
    assert all(f.path == "goapp/go.mod" for f in findings)


def test_gosec_cwe_and_severity(tmp_path, project):
    findings = _parse(tmp_path, "gosec", project)
    by_rule = {f.sources[0].rule_id: f for f in findings}
    assert "G404" in by_rule
    assert "CWE-338" in by_rule["G404"].cwes
    assert by_rule["G404"].severity == Severity.HIGH
    assert by_rule["G404"].path == "goapp/main.go"
    assert by_rule["G404"].start_line == 15


def test_bandit_and_semgrep_titles(tmp_path, project):
    bandit = _parse(tmp_path, "bandit", project)
    assert any("CWE-78" in f.cwes for f in bandit)
    assert all(f.path.startswith("pyapp/") for f in bandit)
    semgrep = _parse(tmp_path, "semgrep", project)
    assert semgrep and all(not f.title.startswith("Semgrep Finding") for f in semgrep)


def test_trivy_dependency_fields(tmp_path, project):
    findings = _parse(tmp_path, "trivy-fs", project)
    deps = [f for f in findings if f.kind == Kind.DEPENDENCY]
    req = [f for f in deps if f.package == "requests"]
    assert req and req[0].installed_version == "2.19.0" and req[0].fixed_version
    assert req[0].path == "pyapp/requirements.txt"
    iac = [f for f in findings if f.kind == Kind.IAC]
    assert iac and iac[0].path == "Dockerfile"


def test_secret_findings_are_redacted(tmp_path, project):
    (project / "creds.py").write_text('API = "AKIAABCDEFGHIJKLMNOP"\n')
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "rules": [
                            {
                                "id": "aws-access-key-id",
                                "shortDescription": {"text": "AWS Access Key ID"},
                                "properties": {"tags": ["secret", "CRITICAL"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "aws-access-key-id",
                        "level": "error",
                        "message": {
                            "text": 'Artifact: creds.py\nMatch: API = "AKIAABCDEFGHIJKLMNOP"'
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "creds.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    f = tmp_path / "trivy-fs.sarif"
    f.write_text(json.dumps(doc))
    [finding] = parse_sarif(f, project)
    assert finding.kind == Kind.SECRET
    dumped = finding.model_dump_json()
    assert "AKIAABCDEFGHIJKLMNOP" not in dumped
    assert finding.anchor


def test_advisory_text_is_kept_for_triage(tmp_path, project):
    # pip-audit/trivy put "which function, under which conditions" in the rule description,
    # not in the result message. Triage needs it to judge reachability (first real run).
    findings = _parse(tmp_path, "trivy-fs", project)
    cve = next(f for f in findings if "CVE-2022-32149" in f.vuln_ids)
    assert "Accept-Language" in cve.sources[0].description
    assert len(cve.sources[0].description) <= 1500
    secrets = [f for f in findings if f.kind == Kind.SECRET]
    assert all(s.description == "" for f in secrets for s in f.sources)
