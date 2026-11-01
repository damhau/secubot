"""secubot: scheduled, hardened security remediation pipeline driven by Claude Code."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("secubot")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0+local"
