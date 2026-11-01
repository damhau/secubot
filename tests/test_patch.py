from __future__ import annotations

from conftest import cluster_by

from secubot.config import SecfixConfig
from secubot.patch import diffstat, parse_diff, validate_patch

GOOD = """diff --git a/goapp/main.go b/goapp/main.go
index 1111111..2222222 100644
--- a/goapp/main.go
+++ b/goapp/main.go
@@ -16,7 +16,7 @@
 func run(name string) error {
-\tcmd := exec.Command("sh", "-c", name)
+\tcmd := exec.Command(name)
 \treturn cmd.Run()
 }
"""


def _file(path: str, body: str = "+x\n", header: str = "") -> str:
    return (
        f"diff --git a/{path} b/{path}\n{header}--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-y\n{body}"
    )


def test_good_patch(report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    assert validate_patch(GOOD, c, SecfixConfig()) == []
    [ch] = parse_diff(GOOD)
    assert (ch.path, ch.added, ch.removed) == ("goapp/main.go", 1, 1)
    assert diffstat(GOOD) == "goapp/main.go | +1 -1"


def test_rejections(report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    cfg = SecfixConfig()
    cases = {
        "": "empty",
        _file(".github/workflows/ci.yml"): "protected path",
        _file(".secfix.yml"): "protected path",
        _file("internal/auth/login.go"): "auth/crypto",
        _file("goapp/main.go", header="old mode 100644\nnew mode 100755\n"): "executable",
        _file("goapp/new.go", header="new file mode 100644\n"): "new files",
        _file("goapp/main.go", header="deleted file mode 100644\n"): "deleting",
        _file("goapp/main.go", body='+key = "sk-ant-api03-' + "A" * 30 + '"\n'): "Anthropic",
        _file("goapp/main.go", body="+-----BEGIN RSA PRIVATE KEY-----\n"): "private key",
        _file("goapp/main.go", body='+t := "ghp_' + "a" * 36 + '"\n'): "GitHub token",
        "diff --git a/goapp/main.go b/goapp/main.go\nBinary files a/x and b/x differ\n": "binary",
        "diff --git a/goapp/old.go b/goapp/new.go\nsimilarity index 90%\n"
        "rename from goapp/old.go\nrename to goapp/new.go\n": "renames",
    }
    for diff, expected in cases.items():
        problems = validate_patch(diff, c, cfg)
        assert any(expected in p for p in problems), (expected, problems)


def test_size_limits(report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    cfg = SecfixConfig.model_validate({"fix": {"max_changed_lines": 3, "max_changed_files": 1}})
    big = _file("goapp/main.go", body="+a\n+b\n+c\n+d\n") + _file("goapp/other.go")
    problems = validate_patch(big, c, cfg)
    assert any("max_changed_lines" in p for p in problems)
    assert any("max_changed_files" in p for p in problems)


def test_sensitive_path_allowed_when_finding_is_there(report):
    c = cluster_by(report, path="goapp/main.go", line=19)
    cfg = SecfixConfig.model_validate({"fix": {"sensitive_paths": ["goapp/main.go"]}})
    assert validate_patch(GOOD, c, cfg) == []


def test_env_secret_values_are_caught(report, monkeypatch):
    c = cluster_by(report, path="goapp/main.go", line=19)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "not-a-real-key-but-long-enough")
    diff = _file("goapp/main.go", body='+x := "not-a-real-key-but-long-enough"\n')
    assert any("ANTHROPIC_API_KEY" in p for p in validate_patch(diff, c, SecfixConfig()))
