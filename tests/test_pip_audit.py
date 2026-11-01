from __future__ import annotations

import json

from conftest import PROJECT, SARIF

from secubot.models import Kind
from secubot.pip_audit import pip_audit_to_sarif
from secubot.sarif import parse_sarif


def test_conversion(tmp_path):
    report = json.loads((SARIF / "pip-audit.json").read_text())
    doc = pip_audit_to_sarif(report, "pyapp/requirements.txt", PROJECT)
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "pip-audit"
    ids = [r["ruleId"] for r in run["results"]]
    assert len(ids) == len(set(ids)), "pip-audit repeats advisories; they are deduplicated"
    lines = {
        r["properties"]["package"]: r["locations"][0]["physicalLocation"]["region"]["startLine"]
        for r in run["results"]
    }
    assert lines.get("requests") == 1
    if "pyyaml" in {k.lower() for k in lines}:
        assert 2 in lines.values()
    f = tmp_path / "pip-audit.sarif"
    f.write_text(json.dumps(doc))
    findings = parse_sarif(f, PROJECT)
    assert findings and all(x.kind == Kind.DEPENDENCY for x in findings)
    req = [x for x in findings if x.package == "requests"]
    assert req and req[0].installed_version == "2.19.0"
    assert any(v.startswith("CVE-") for x in req for v in x.vuln_ids)


def test_empty_report():
    doc = pip_audit_to_sarif({"dependencies": []}, "")
    assert doc["runs"][0]["results"] == []


def test_advisories_mentioning_other_cves_are_not_merged(tmp_path):
    """PYSEC-2021-142's description cites CVE-2020-1747 (another advisory). They must stay
    separate findings, and the cluster must target the version fixing both (5.4)."""
    from secubot.config import SecfixConfig
    from secubot.normalise import normalise

    report = json.loads((SARIF / "pip-audit.json").read_text())
    doc = pip_audit_to_sarif(report, "pyapp/requirements.txt", PROJECT)
    f = tmp_path / "pip-audit.sarif"
    f.write_text(json.dumps(doc))
    rep = normalise([f], PROJECT, SecfixConfig())
    [pyyaml] = [c for c in rep.clusters if c.package == "pyyaml"]
    assert pyyaml.target_version == "5.4"
    assert len(pyyaml.findings) == 2
    assert {"CVE-2020-14343", "CVE-2020-1747"} <= set(pyyaml.vuln_ids)
