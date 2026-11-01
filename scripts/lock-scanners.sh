#!/usr/bin/env bash
# Regenerate the hash-locked requirement files after bumping a version in versions.env.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../scanners/versions.env
source "$here/scanners/versions.env"
cd "$here/scanners/requirements"
printf 'semgrep==%s\n' "$SEMGREP_VERSION" >semgrep.in
printf 'bandit[sarif]==%s\n' "$BANDIT_VERSION" >bandit.in
printf 'pip-audit==%s\n' "$PIP_AUDIT_VERSION" >pip-audit.in
for t in semgrep bandit pip-audit; do
  uv pip compile --quiet --universal --python-version "$SCANNER_PYTHON" --generate-hashes \
    --no-header --output-file "$t.txt" "$t.in"
done

# Trivy release checksums (published by the release workflow next to the tarballs).
sums="$(curl -fsSL --retry 3 \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt")"
for pair in 64BIT:64bit ARM64:ARM64; do
  key="${pair%%:*}" arch="${pair##*:}"
  sha="$(awk -v f="trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz" '$2 == f { print $1 }' <<<"$sums")"
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "no checksum for Linux-${arch}" >&2; exit 1; }
  sed -i -E "s/^TRIVY_SHA256_LINUX_${key}=.*/TRIVY_SHA256_LINUX_${key}=${sha}/" \
    "$here/scanners/versions.env"
done
echo "updated scanners/requirements/*.txt and the trivy checksums in scanners/versions.env"
