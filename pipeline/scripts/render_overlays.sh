#!/usr/bin/env bash
#
# Render one GitOps repository's Kustomize overlays into a single YAML stream.
#
# Usage: render_overlays.sh <repo-root> <out-file> <overlay-path>...
#
# `kubectl kustomize` needs no cluster and no credentials — it is a pure local
# render — so this step stays offline and deterministic.
#
# Each overlay is preceded by an explicit `---` so documents from two overlays can
# never be concatenated into one, which would hide the second overlay's first
# resource from the image scanner.

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $(basename "$0") <repo-root> <out-file> <overlay-path>..." >&2
  exit 2
fi

repo_root="$1"
out_file="$2"
shift 2

if ! command -v kubectl >/dev/null 2>&1; then
  echo "error: kubectl not found on PATH; it is required for 'kubectl kustomize'" >&2
  exit 1
fi

if [[ ! -d "$repo_root" ]]; then
  echo "error: repository root not found: $repo_root" >&2
  exit 1
fi

mkdir -p "$(dirname "$out_file")"
: >"$out_file"

for overlay in "$@"; do
  overlay_dir="$repo_root/$overlay"
  if [[ ! -d "$overlay_dir" ]]; then
    echo "error: overlay not found: $overlay_dir" >&2
    exit 1
  fi

  echo "rendering $overlay" >&2
  {
    echo "---"
    echo "# rendered from $overlay"
  } >>"$out_file"

  if ! kubectl kustomize "$overlay_dir" >>"$out_file"; then
    echo "error: kubectl kustomize failed for $overlay_dir" >&2
    exit 1
  fi
done

# An empty render is a wrong path far more often than an empty overlay, and it
# would otherwise surface as "this repository deploys nothing" in the report.
if [[ ! -s "$out_file" ]]; then
  echo "error: rendered output is empty: $out_file" >&2
  exit 1
fi

echo "rendered $# overlay(s) into $out_file" >&2
