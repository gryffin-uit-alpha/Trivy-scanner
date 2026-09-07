# Pipeline — orchestration and image discovery

Everything in this directory is the **orchestrator's** half of the system. It checks
out repositories, renders overlays, discovers images, authenticates to the registry,
runs Trivy, and hands the results to the Python application. The application does no
part of that (constitution Principle I), and nothing in here is part of the
distribution — `pyproject.toml` builds from `src/` only.

```
pipeline/
├── azure-pipelines.yml          the orchestrator; the only file you edit to add a repository
├── templates/scan-repo.yml      one fan-out job per GitOps repository
└── scripts/
    ├── render_overlays.sh       kubectl kustomize -> one rendered YAML stream
    ├── discover_images.py       rendered YAML -> sorted unique image references
    ├── make_manifest.py         references -> manifest fragment + Trivy scan plan
    ├── scan_images.sh           scan plan -> one Trivy JSON per image
    ├── merge_manifests.py       fragments -> the one manifest the application reads
    └── image_ref.py             the reference grammar shared by discovery and the producer
```

Every Python module here is both an importable library and a `python3 -m` entry
point, so each step can be unit-tested without a build agent and reproduced locally
by hand. Standard library only, same as the application.

## Job graph

```
prepare ──┬─> scan_<repo_a> ──┐
          └─> scan_<repo_b> ──┴─> report ──> gate
```

| Job | Does | Fails when |
| --- | --- | --- |
| `prepare` | Stamps the scan date (the one clock read in the whole system) and warms the Trivy DB cache once for the fan-out. | The DB cannot be downloaded. |
| `scan_*` | Renders overlays, discovers images, produces the fragment and plan, scans, publishes `scan-<repo>`. | Overlays fail to render, a reference is unparsable, or *every* image fails to scan. |
| `report` | Merges fragments, runs `trivy_report`, publishes reports and the rolling history. | Report generation itself fails (exit 1) or no fragment exists at all. |
| `gate` | Turns the recorded exit code into the build result. | Exit code is 3 (threshold met), 1, or missing. |

Two properties are deliberate and worth not breaking:

- **`report` depends on every `scan_*` job but is conditioned on `succeeded('prepare')`.**
  One repository failing must not deny every other repository its report. The
  missing repository is reported as *unscanned*, not as clean.
- **The gate is a separate, later job.** `report` exits 0 for application exit codes
  0, 2 and 3, so its publish steps always run. A threshold breach can therefore never
  stop today's history from being persisted — which matters because a breach is the
  steady state once a permanent CRITICAL exists, and a frozen baseline would mean no
  trends from that day on.

## Data flow

```
GitOps repo ──render──> rendered.yaml ──discover──> images.json
                                                       │
                                              make_manifest
                                                  ┌────┴────┐
                                            plan.tsv    manifest-fragment.json
                                                │              │
                                          scan_images.sh   merge_manifests
                                                │              │
                                          results/*.json   input/manifest.json
                                                └──────┬───────┘
                                                  trivy_report
                                                       │
                                        output/*.md  +  history/<scan-date>.json
```

`make_manifest.py` emits the plan and the fragment from a single in-memory list, so
the scanner cannot write a file the manifest does not point at. Result paths are
namespaced by the slugged repository name and fingerprinted with a hash of the full
reference, so two repositories scanning the same image cannot overwrite each other.

The rendered YAML is written to `$(Agent.TempDirectory)`, **not** into the published
artifact: a GitOps overlay may contain `Secret` resources and an artifact is readable
by anyone with access to the run.

## Add a GitOps repository

Three edits, all in `pipeline/azure-pipelines.yml`, all marked
`ADD A REPOSITORY HERE (n/3)`. No Python change, and no change in this README.

1. **`resources.repositories`** — declare the repository and the branch to scan:

   ```yaml
       - repository: gitops_orders          # alias; underscores only
         type: git
         name: gitops-orders                # the Azure DevOps repository name
         ref: refs/heads/main
   ```

   This list must be static YAML. Azure DevOps resolves it before the run starts, so
   it cannot be generated from a config file — which is why the list lives here
   rather than in a `scan-targets.yml`.

2. **The `scannedRepositories` variable** — append the display name:

   ```yaml
     - name: scannedRepositories
       value: 'gitops-payments,gitops-platform,gitops-orders'
   ```

   Used only to warn when a repository produced no results, so a silently skipped
   repository cannot look like a clean one.

3. **A template instantiation** — and add its job name to `report`'s `dependsOn`:

   ```yaml
     - template: templates/scan-repo.yml
       parameters:
         repository: gitops-orders          # names the report file and is the trend key
         checkout: gitops_orders            # the alias from step 1
         overlays:
           - overlays/production
   ```

   ```yaml
     - job: report
       dependsOn:
         - prepare
         - scan_gitops_payments
         - scan_gitops_platform
         - scan_gitops_orders               # `-` becomes `_` in the job name
   ```

`repository` is the trend key: renaming it starts a new trend line and the old name
is then reported as unscanned until it ages out of the history window.

## Secrets

Off by default. The `registryCredentials` parameter is `false`, which means no variable
group is referenced and Trivy is handed no credentials at all — the mode to run in while
the images being scanned are public.

Set it `true` once the images live in Artifactory, and create one variable group,
`trivy-scanner-secrets`, with both values **marked secret**:

| Variable | Value |
| --- | --- |
| `TRIVY_USERNAME` | Artifactory user, or the identity-token principal. |
| `TRIVY_PASSWORD` | Artifactory identity token. Read-only pull scope is enough. |

The parameter is compile-time because `- group:` is resolved before any job starts:
naming a group that does not exist fails the pipeline outright, so this cannot be a
runtime variable.

They are mapped into the environment of the Trivy step only (`templates/scan-repo.yml`),
forwarded to the container by name and only when non-empty (`docker run -e TRIVY_USERNAME`),
and never expanded into a script body — `tests/pipeline/test_shell_steps.py` fails the
build if one ever is, because a token printed once lives in the build log forever.

"Only when non-empty" is load-bearing in both directions: an empty username is a login
attempt that gets refused, not an anonymous pull, and an unresolved `$(TRIVY_USERNAME)`
macro would be forwarded as its own literal text.

## Tuning

All in `azure-pipelines.yml` `variables`:

| Variable | Default | Notes |
| --- | --- | --- |
| `trivyImage` | `aquasec/trivy:0.73.0` | Pinned: Trivy's JSON is a contract this application parses. Point at an Artifactory mirror if Docker Hub is unreachable. |
| `trivyDbRepository` | *(empty)* | OCI mirror for the vulnerability DB. Read by Trivy itself. |
| `trivyTimeout` | `10m` | Per image. |
| `retentionDays` | `90` | The application prunes the history directory to this window. Because every run republishes the whole directory, this — not Azure DevOps artifact retention — defines how much history exists. Keep ADO retention at or above it. |
| `failOn` | *(empty)* | No threshold: this is a daily report, and a nightly build that fails every night from the first permanent CRITICAL onward stops being read. Set a space-separated list of `SEVERITY=COUNT` to gate, e.g. `'CRITICAL=1 HIGH=25'`, evaluated against the unique-image grand total. |

## History

The history directory is a rolling archive, not a single file:

1. `report` downloads the previous `scan-history` artifact, with
   `allowFailedBuilds` and `allowPartiallySucceededBuilds` set — a run that met the
   threshold is a *failed* run and holds the newest history.
2. The application adds `<scan-date>.json` and prunes past the retention window.
3. `report` republishes the **whole** directory.

The download is `continueOnError`: the first ever run has no artifact, and the
application treats an absent baseline as a supported state (every count reads as new).

## Run it locally

No Azure DevOps and no agent needed. From the repository root:

```bash
# 1. Render (needs kubectl; skip it and hand-write a YAML file to try the rest)
pipeline/scripts/render_overlays.sh ../gitops-payments /tmp/rendered.yaml overlays/production

# 2. Discover
python3 -m pipeline.scripts.discover_images \
  --rendered /tmp/rendered.yaml --out /tmp/staging/images.json

# 3. Fragment + plan
python3 -m pipeline.scripts.make_manifest \
  --repository gitops-payments \
  --images-json /tmp/staging/images.json \
  --fragment-out /tmp/staging/manifest-fragment.json \
  --plan-out /tmp/staging/plan.tsv

# 4. Scan (needs docker and registry credentials)
TRIVY_IMAGE=aquasec/trivy:0.73.0 TRIVY_CACHE_DIR=/tmp/trivy-cache \
  pipeline/scripts/scan_images.sh /tmp/staging/plan.tsv /tmp/input

# 5. Merge, then report
python3 -m pipeline.scripts.merge_manifests \
  --fragment /tmp/staging/manifest-fragment.json \
  --scan-date 2026-08-17 --out /tmp/input/manifest.json

PYTHONPATH=src python3 -m trivy_report \
  --input /tmp/input --manifest /tmp/input/manifest.json \
  --history-dir /tmp/history --output-dir /tmp/output \
  --scan-date 2026-08-17 --retention-days 90     # add --fail-on CRITICAL=1 to gate
```

Steps 1 and 4 are the only ones that need infrastructure. To exercise the whole chain
with neither Trivy nor kubectl, use the committed fixtures the way
`tests/pipeline/test_producer_satisfies_the_app.py` does, or follow
`specs/001-trivy-vuln-reports/quickstart.md`.

## Tests

```bash
python3 -m pytest tests/pipeline -q
```

Covers the reference grammar, discovery against a rendered-Kustomize fixture full of
deliberate decoys (ConfigMap `data`, annotations, labels, `matchLabels`, block
scalars), the manifest producer's schema conformance, the merge rules, and one
end-to-end test asserting that the real application accepts what the real producer
emits. The shell scripts get `bash -n`, an executable-bit check, a credential-leak
check, and `shellcheck` when it is installed.
