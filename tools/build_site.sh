#!/usr/bin/env bash
# Build the GitHub Pages site: TL;DR post (site/index.html) + Inspect log bundle.
# Usage: tools/build_site.sh <output-dir>
# Only the two re-scored N=50 logs are bundled. Do NOT add the 2026-11-02 logs:
# they predate the per-sample sandbox and contain host environment dumps.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:?usage: tools/build_site.sh <output-dir>}"
src="$(mktemp -d)"
trap 'rm -rf "$src"' EXIT

cp logs/2026-11-11T15-11-41-00-00_qwen-continue_YCkBcDAd9AfzeTJXXfWNuo-rescored.eval \
   logs/2026-11-11T19-16-24-00-00_qwen-continue_bk2BwGrnSxNwuES2aSXYBJ-rescored.eval "$src/"

rm -rf "$out"
mkdir -p "$out"
.venv/bin/inspect view bundle --log-dir "$src" --output-dir "$out/logs"
cp site/index.html "$out/index.html"
cp docs/assets/routify-dates.png "$out/routify-dates.png"
touch "$out/.nojekyll"
echo "built $out"
