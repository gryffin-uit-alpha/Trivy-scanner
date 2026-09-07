#!/usr/bin/env bash
#
# Scan every image in a plan with Trivy, writing one JSON result per image.
#
# Usage: scan_images.sh <plan.tsv> <results-root>
#
# The plan is `make_manifest.py --plan-out`: one `reference<TAB>result_file` line
# per image. Result paths come from the manifest producer, never from this script —
# the manifest is the authority on where a result lives, and inventing a path here
# is how findings get attributed to the wrong image.
#
# Environment:
#   TRIVY_IMAGE            Pinned Trivy container image (required).
#   TRIVY_CACHE_DIR        Host directory holding the vulnerability DB (required).
#   TRIVY_USERNAME         Registry user. Forwarded by name when non-empty, never printed.
#   TRIVY_PASSWORD         Registry token/password. Same. Both are omitted entirely for a
#                          public registry: an empty username is not "no credentials", it
#                          is a credential Trivy may try and be refused for.
#   TRIVY_SKIP_DB_UPDATE   "true" when a warm DB cache was restored.
#   TRIVY_DB_REPOSITORY    Optional mirror for the vulnerability DB. Read by Trivy
#                          itself, so no flag is needed here; set it when the agent
#                          cannot reach the default OCI registry.
#   TRIVY_TIMEOUT          Per-image timeout. Default 10m.
#   HTTP_PROXY, HTTPS_PROXY, NO_PROXY (and lowercase)
#                          Forwarded into the container when set. Trivy reaches the
#                          registry and the DB repository from *inside* the container,
#                          so on a proxy-only network it fails without these.
#
# Failure policy: one image failing to scan is recoverable. Its result file is
# removed so the application records a FILE_MISSING failure naming the image and
# exits 2 — a visible gap in the report rather than a silent absence. Every image
# failing is not recoverable: that is a broken agent or bad credentials, so the job
# fails and this repository is reported as unscanned instead of as clean.

set -uo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $(basename "$0") <plan.tsv> <results-root>" >&2
  exit 2
fi

plan_file="$1"
results_root="$2"

: "${TRIVY_IMAGE:?TRIVY_IMAGE must be set to a pinned Trivy image}"
: "${TRIVY_CACHE_DIR:?TRIVY_CACHE_DIR must be set}"
timeout="${TRIVY_TIMEOUT:-10m}"

if [[ ! -f "$plan_file" ]]; then
  echo "error: scan plan not found: $plan_file" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker not found on PATH; it runs the pinned Trivy image" >&2
  exit 1
fi

mkdir -p "$results_root" "$TRIVY_CACHE_DIR"

# Forward by name only, and only when set, so an unset or empty variable stays unset
# inside the container rather than becoming an empty value Trivy would try to use.
# Credentials matter most here: an empty TRIVY_USERNAME against a public registry is
# a rejected login, not an anonymous pull.
env_args=()
for var in TRIVY_USERNAME TRIVY_PASSWORD TRIVY_DB_REPOSITORY \
  HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
  [[ -n "${!var:-}" ]] && env_args+=(-e "$var")
done

extra_args=()
if [[ "${TRIVY_SKIP_DB_UPDATE:-false}" == "true" ]]; then
  # Only safe when the cache was restored; without a DB, Trivy would fail hard.
  extra_args+=(--skip-db-update --skip-java-db-update)
fi

total=0
failed=0
failed_refs=()

while IFS=$'\t' read -r ref result_file; do
  [[ -z "${ref:-}" ]] && continue
  if [[ -z "${result_file:-}" ]]; then
    echo "error: malformed plan line for $ref (no result_file column)" >&2
    exit 1
  fi

  total=$((total + 1))
  mkdir -p "$results_root/$(dirname "$result_file")"

  echo "scanning $ref -> $result_file" >&2
  if docker run --rm \
    "${env_args[@]}" \
    -v "$TRIVY_CACHE_DIR:/root/.cache/trivy" \
    -v "$results_root:/results" \
    "$TRIVY_IMAGE" image \
    --format json \
    --output "/results/$result_file" \
    --scanners vuln \
    --no-progress \
    --timeout "$timeout" \
    "${extra_args[@]}" \
    "$ref"; then
    continue
  fi

  failed=$((failed + 1))
  failed_refs+=("$ref")
  # A partial or absent file both become failures downstream, but FILE_MISSING
  # names the image in the report's Failures table, which MALFORMED_JSON cannot.
  rm -f "$results_root/$result_file"
  echo "warning: Trivy failed for $ref; it will be reported as a missing result" >&2
done <"$plan_file"

echo "scanned $((total - failed))/$total image(s)" >&2

if ((total > 0 && failed == total)); then
  echo "error: every image failed to scan (${failed_refs[*]})" >&2
  exit 1
fi

exit 0
