#!/usr/bin/env bash
# Install the pinned scanners into $SECUBOT_TOOLS (default: $RUNNER_TEMP/secubot-tools).
#   usage: install-scanners.sh trivy-fs govulncheck gosec bandit pip-audit semgrep
# trivy is verified against a pinned sha256; Go tools go through the Go checksum database;
# Python tools are installed from hash-locked requirement files into isolated venvs.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../scanners/versions.env
source "$here/scanners/versions.env"

tools_dir="${SECUBOT_TOOLS:-${RUNNER_TEMP:-/tmp}/secubot-tools}"
bin="$tools_dir/bin"
mkdir -p "$bin"

install_trivy() {
  command -v "$bin/trivy" >/dev/null 2>&1 && return
  local arch sha
  case "$(uname -m)" in
    x86_64) arch=64bit; sha="$TRIVY_SHA256_LINUX_64BIT" ;;
    aarch64 | arm64) arch=ARM64; sha="$TRIVY_SHA256_LINUX_ARM64" ;;
    *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
  esac
  local tgz="trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz"
  local tmp
  tmp="$(mktemp -d)"
  curl -fsSL --retry 3 -o "$tmp/$tgz" \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tgz}"
  echo "${sha}  $tmp/$tgz" | sha256sum -c --quiet -
  tar -xzf "$tmp/$tgz" -C "$tmp" trivy
  install -m 0755 "$tmp/trivy" "$bin/trivy"
  rm -rf "$tmp"
}

install_go_tool() { # $1 = module path with @version
  command -v go >/dev/null || { echo "go is required to install $1" >&2; exit 1; }
  GOBIN="$bin" GOFLAGS=-mod=mod GOTOOLCHAIN=local go install "$1"
}

install_py_tool() { # $1 = tool name (requirements file), $2 = executable
  [ -x "$bin/$2" ] && return
  local venv="$tools_dir/venvs/$1"
  uv venv --quiet --python "$SCANNER_PYTHON" "$venv"
  uv pip install --quiet --python "$venv/bin/python" --require-hashes --no-deps \
    -r "$here/scanners/requirements/$1.txt"
  ln -sf "$venv/bin/$2" "$bin/$2"
}

for tool in "$@"; do
  case "$tool" in
    trivy | trivy-fs | trivy-image) install_trivy ;;
    govulncheck) install_go_tool "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ;;
    gosec) install_go_tool "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}" ;;
    bandit) install_py_tool bandit bandit ;;
    pip-audit) install_py_tool pip-audit pip-audit ;;
    semgrep) install_py_tool semgrep semgrep ;;
    *) echo "unknown tool: $tool" >&2; exit 1 ;;
  esac
done

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$bin" >>"$GITHUB_PATH"
fi
echo "scanners installed in $bin" >&2
