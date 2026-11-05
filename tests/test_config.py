from __future__ import annotations

import datetime as dt

import pytest
from pydantic import ValidationError

from secubot.config import SecfixConfig, Suppression, detect_languages, load_config


def test_defaults():
    cfg = SecfixConfig()
    assert cfg.models.triage == cfg.models.fix == "claude-opus-5-5"
    assert cfg.models.effort == "high"
    assert cfg.policy.dependencies == "breaking-only"
    assert cfg.protected_spec().match_file(".github/workflows/x.yml")
    assert cfg.protected_spec().match_file("deep/dir/CLAUDE.md")
    assert not cfg.protected_spec().match_file("src/main.go")


def test_unknown_keys_are_rejected():
    with pytest.raises(ValidationError):
        SecfixConfig.model_validate({"policy": {"max_pr": 3}})
    with pytest.raises(ValidationError):
        SecfixConfig.model_validate({"fix": {"max_attempts": 50}})


def test_suppression_validation():
    with pytest.raises(ValidationError):
        Suppression(reason="no selector at all", expires=dt.date(2027, 1, 1))
    with pytest.raises(ValidationError):
        Suppression(rule="G404", reason="short", expires=dt.date(2027, 1, 1))
    s = Suppression(rule="G404", reason="simulation jitter only", expires=dt.date(2027, 1, 1))
    assert s.active(dt.date(2027, 1, 1)) and not s.active(dt.date(2027, 1, 2))


def test_load_and_detect(project):
    assert load_config(project) == SecfixConfig()
    (project / ".secfix.yml").write_text("policy:\n  max_prs: 1\nlabels: [security, ' bot ']\n")
    cfg = load_config(project)
    assert cfg.policy.max_prs == 1 and cfg.labels == ["security", "bot"]
    assert detect_languages(project, cfg) == ["go", "python"]
    (project / ".secfix.yml").write_text("- not a mapping\n")
    with pytest.raises(ValueError):
        load_config(project)


def test_trivy_image_target():
    ok = SecfixConfig.model_validate({"scanners": {"trivy_image": {"target": "all-in-one"}}})
    assert ok.scanners.trivy_image.target == "all-in-one"
    assert SecfixConfig().scanners.trivy_image.target is None
    for bad in ["--output=/tmp/x", "a b", "", "-q", "1stage"]:
        with pytest.raises(ValidationError):
            SecfixConfig.model_validate({"scanners": {"trivy_image": {"target": bad}}})
