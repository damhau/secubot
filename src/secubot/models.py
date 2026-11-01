"""Shared data model: findings (deduplicated across tools) and clusters (units of work)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

FINGERPRINT_SCHEME = "v1"
BRANCH_PREFIX = "secfix/"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str | None, default: Severity | None = None) -> Severity | None:
        if value is None:
            return default
        v = str(value).strip().lower()
        aliases = {
            "moderate": "medium",
            "warning": "medium",
            "error": "high",
            "note": "low",
            "negligible": "info",
            "unknown": "info",
            "none": "info",
        }
        v = aliases.get(v, v)
        try:
            return cls(v)
        except ValueError:
            return default

    @classmethod
    def from_score(cls, score: float) -> Severity:
        # GitHub code scanning convention for `security-severity` (CVSS-like).
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def max_severity(values: list[Severity]) -> Severity:
    return max(values, key=lambda s: s.rank) if values else Severity.INFO


class Kind(StrEnum):
    DEPENDENCY = "dependency"  # vulnerable third-party package / toolchain / base image
    CODE = "code"  # SAST finding in first-party code
    IAC = "iac"  # Dockerfile / Terraform / Kubernetes misconfiguration
    SECRET = "secret"  # noqa: S105 - hard-coded credential finding
    LICENSE = "license"  # licence policy finding (reported, never auto-fixed)


class Reachability(StrEnum):
    YES = "yes"  # a tool proved the vulnerable code is called (govulncheck "error")
    NO = "no"  # a tool proved it is not called (govulncheck "warning"/"note")
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return {"yes": 2, "unknown": 1, "no": 0}[self.value]


def merge_reachability(values: list[Reachability]) -> Reachability:
    """YES beats NO beats UNKNOWN: a proof of reachability wins, then a proof of absence."""
    if Reachability.YES in values:
        return Reachability.YES
    if Reachability.NO in values:
        return Reachability.NO
    return Reachability.UNKNOWN


class Source(BaseModel):
    """One raw scanner result that contributed to a finding."""

    tool: str  # SARIF file stem, e.g. "gosec", "trivy-fs" (also the scanner to re-run)
    rule_id: str
    level: str = "warning"
    message: str = ""
    help_uri: str | None = None


class Finding(BaseModel):
    """A deduplicated finding: same weakness/vulnerability at the same location."""

    fingerprint: str = ""
    kind: Kind
    severity: Severity
    title: str
    path: str
    start_line: int | None = None
    end_line: int | None = None
    snippet: str | None = None
    anchor: str = ""  # location anchor (line-content hash, or package for dependencies)
    vuln_ids: list[str] = Field(default_factory=list)  # CVE / GHSA / GO / PYSEC ids
    cwes: list[str] = Field(default_factory=list)  # "CWE-78"
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    reachable: Reachability = Reachability.UNKNOWN
    call_path: list[str] = Field(default_factory=list)  # e.g. govulncheck call stack
    sources: list[Source] = Field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted({s.tool for s in self.sources})

    @property
    def rule_ids(self) -> list[str]:
        return sorted({s.rule_id for s in self.sources})


class Cluster(BaseModel):
    """Unit of work: one branch, one triage, one PR or issue."""

    id: str
    kind: Kind
    key: str  # human-readable cluster key, for debugging
    title: str
    severity: Severity
    reachable: Reachability
    path: str
    start_line: int | None = None
    package: str | None = None
    installed_version: str | None = None
    target_version: str | None = None
    breaking_upgrade: bool | None = None
    findings: list[Finding]

    @property
    def branch(self) -> str:
        return f"{BRANCH_PREFIX}{self.id}"

    @property
    def tools(self) -> list[str]:
        return sorted({t for f in self.findings for t in f.tools})

    @property
    def vuln_ids(self) -> list[str]:
        return sorted({v for f in self.findings for v in f.vuln_ids})

    @property
    def cwes(self) -> list[str]:
        return sorted({c for f in self.findings for c in f.cwes})

    @property
    def rule_ids(self) -> list[str]:
        return sorted({r for f in self.findings for r in f.rule_ids})

    @property
    def fingerprints(self) -> list[str]:
        return sorted({f.fingerprint for f in self.findings})

    @property
    def paths(self) -> list[str]:
        return sorted({f.path for f in self.findings})


class ScanReport(BaseModel):
    """Output of the normalise step."""

    raw_results: int
    findings: list[Finding]
    clusters: list[Cluster]
    tool_status: dict[str, str] = Field(default_factory=dict)
    base_sha: str = ""
    """Commit that was scanned; fixes are applied on top of it."""

    def cluster(self, cluster_id: str) -> Cluster:
        for c in self.clusters:
            if c.id == cluster_id:
                return c
        raise KeyError(f"unknown cluster {cluster_id}")
