from __future__ import annotations

from conftest import cluster_by, prepare_sarif

from secubot.config import SecfixConfig
from secubot.models import Kind, Reachability
from secubot.normalise import best_fixed_version, is_breaking_upgrade, max_version, normalise


def test_counts_and_ordering(report):
    assert report.raw_results == 33
    assert len(report.findings) == 28
    assert len(report.clusters) == 14  # IaC: one cluster per file
    ranks = [c.severity.rank for c in report.clusters]
    assert ranks == sorted(ranks, reverse=True)


def test_same_sink_across_tools_is_merged(report):
    cmd = cluster_by(report, path="goapp/main.go", line=19)
    assert {"gosec", "semgrep"} <= set(cmd.tools)
    assert "CWE-78" in cmd.cwes
    shell = cluster_by(report, path="pyapp/app.py", line=13)
    assert {"bandit", "semgrep"} <= set(shell.tools)


def test_dependency_aliases_and_reachability_merge(report):
    xtext = cluster_by(report, package="golang.org/x/text")
    assert set(xtext.tools) == {"govulncheck", "trivy-fs"}
    assert xtext.reachable == Reachability.YES
    assert xtext.target_version == "0.41.0"
    assert xtext.breaking_upgrade is True  # 0.x minor bump
    # one finding per vulnerability, not one per tool
    ids = [f.vuln_ids for f in xtext.findings]
    assert len(ids) == len({tuple(sorted(i)) for i in ids})


def test_unreachable_stdlib_cluster(report):
    stdlib = cluster_by(report, package="stdlib")
    assert stdlib.reachable == Reachability.NO
    assert stdlib.title.startswith("stdlib: ")


def test_fingerprints_survive_line_shifts(project, tmp_path, cfg):
    before = normalise(prepare_sarif(project, tmp_path / "a"), project, cfg)
    # Unrelated edit above the findings: the scanners would now report line+1, but the
    # fingerprint uses the content of the flagged line, not its number.
    main = project / "goapp" / "main.go"
    main.write_text("// header comment\n" + main.read_text())
    after_dir = tmp_path / "b"
    files = prepare_sarif(project, after_dir)
    for f in files:
        if f.stem in {"gosec", "semgrep"}:
            import json

            doc = json.loads(f.read_text())
            for run in doc["runs"]:
                for r in run["results"]:
                    for loc in r["locations"]:
                        pl = loc["physicalLocation"]
                        if pl["artifactLocation"]["uri"] == "goapp/main.go":
                            pl["region"]["startLine"] += 1
                            pl["region"].pop("snippet", None)
            f.write_text(json.dumps(doc))
    after = normalise(files, project, cfg)
    ids = lambda rep: {c.id for c in rep.clusters if c.path == "goapp/main.go"}  # noqa: E731
    assert ids(before) == ids(after)


def test_skip_paths_drop_findings(project, tmp_path):
    cfg = SecfixConfig.model_validate({"paths": {"skip": ["pyapp/"]}})
    rep = normalise(prepare_sarif(project, tmp_path / "s"), project, cfg)
    assert all(not c.path.startswith("pyapp/") for c in rep.clusters)
    assert any(c.kind == Kind.CODE for c in rep.clusters)


def test_version_helpers():
    assert best_fixed_version("0.3.7", "0.3.8, 0.4.0") == "0.3.8"
    assert max_version(["1.2.0", "1.10.0", "1.9.9"]) == "1.10.0"
    assert is_breaking_upgrade("1.2.3", "2.0.0") is True
    assert is_breaking_upgrade("1.2.3", "1.9.0") is False
    assert is_breaking_upgrade("0.3.7", "0.4.0") is True
    assert is_breaking_upgrade(None, "1.0.0") is None


def test_iac_findings_cluster_per_file(report):
    iac = [c for c in report.clusters if c.kind.value == "iac"]
    assert len(iac) == len({c.path for c in iac})
    docker = next(c for c in iac if c.path == "Dockerfile")
    assert len(docker.findings) > 1 and "more" in docker.title
