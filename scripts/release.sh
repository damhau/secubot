#!/usr/bin/env bash
# Cut a release: stamp the reusable workflow's default secubot-ref with the tag's commit,
# commit, tag vX.Y.Z and move the major tag (v1). Callers pin `@v1` (or a full SHA).
#   usage: scripts/release.sh 1.2.0
set -euo pipefail
version="${1:?usage: release.sh X.Y.Z}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "bad version: $version" >&2; exit 1; }
major="v${version%%.*}"
wf=.github/workflows/secfix.yml

git diff --quiet && git diff --cached --quiet || { echo "working tree not clean" >&2; exit 1; }
# The reusable workflow checks secubot itself out at `secubot-ref`. Point the default at the
# release tag so `uses: org/secubot/.github/workflows/secfix.yml@v1` runs matching code.
sed -i -E "/secubot-ref:/,/default:/ s|(default: ).*|\\1\"v${version}\"|" "$wf"
sed -i -E "s/^version = \".*\"/version = \"${version}\"/" pyproject.toml
uv lock --quiet
git add "$wf" pyproject.toml uv.lock
git commit -q -m "release v${version}"
git tag -a "v${version}" -m "secubot v${version}"
git tag -fa "$major" -m "secubot ${major} -> v${version}"
echo "tagged v${version} and ${major}. Push with:"
echo "  git push origin HEAD v${version} && git push -f origin ${major}"
