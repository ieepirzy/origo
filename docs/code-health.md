# Code health, maintainability and provenance telemetry

This repository measures its own structural health on every CI run, writes the
result to a versioned artifact, and exports derived observations over OTLP.

The immediate goal is a **trustworthy measuring instrument**. Refactoring
policy, quality gates, dashboards and predictive models come after there are
measurements worth trusting.

## Layers

The five layers are kept separate, and the separation is load-bearing rather
than decorative — collapsing any two is what makes a telemetry system
un-migratable later.

| Layer | Where it lives | Rule |
|---|---|---|
| Measurement | `tools/code_health/analyzers/` | Dedicated tools produce observations. Nothing else measures anything. |
| Canonical representation | `code-health.json` (`schema.py`, `normalize.py`) | The source record. Everything else is derived from it. |
| Transport | `otel.py`, `emit.py` | OTLP, plus an optional direct document POST. No backend-specific code. |
| Routing | An OpenTelemetry Collector | CI knows one endpoint. The Collector knows the backends. |
| Policy | `cli.py` (`--gate`) | Gates read normalized measurements. They never decide how data is stored. |

```
analyzers ─► normalized model ─┬─► code-health.json   (canonical, complete)
                               └─► OTLP exporter ─► Collector ─┬─► metrics backend
                                                               ├─► logs/events backend
                                                               ├─► trace backend
                                                               └─► durable analytical storage
```

**OTEL metrics are not the data model.** They are a bounded projection of the
artifact, resolved by dotted path from `metrics.METRICS`, so the metric stream
cannot drift away from the record.

## Running it

```bash
pip install -e ".[dev,code-health,code-health-otel]"

pytest -q --junitxml=reports/junit.xml --cov=origo --cov-report=xml:reports/coverage.xml

python -m tools.code_health \
  --output code-health.json \
  --junit reports/junit.xml \
  --coverage reports/coverage.xml \
  --baseline baseline/code-health.json \
  --gate --emit-otlp --emit-http
```

With no endpoint configured and no baseline available, the artifact is still
produced and the summary is still printed. That is the intended degraded mode,
not a failure.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Analysis completed; no gate violations. |
| 1 | A blocking gate failed (lint in gated paths, failing tests, type errors when gating is enabled). |
| 2 | A required analyzer failed or is missing. The measurement is incomplete and that is treated as serious. |
| 3 | Telemetry emission failed **and** `--blocking-telemetry` was passed. Off by default. |

Telemetry failure is not a build failure by default. Analyzer failure is.
A CI lane that fails because a metrics endpoint is down teaches people to
ignore it.

**Required vs optional analyzers.** radon, ruff and the configured type checker
are required: if one is missing (`unavailable`) or broke (`error`), the run
exits 2. Without that rule a runner that lost radon would emit a snapshot whose
every complexity field is `null`, export no complexity metrics at all, and exit
0 — the series would simply stop, looking from the outside like a repository
nobody touched. The test and security adapters are opt-in per invocation, so
`skipped` there is a configuration choice and never a failure.

## Configuration

`[tool.code_health]` in `pyproject.toml`:

```toml
[tool.code_health]
paths = ["origo"]                          # complexity / LOC / maintainability
lint_paths = ["origo", "tests", "tools"]   # measured for lint
lint_gate_paths = ["origo", "tools"]       # the subset whose findings BLOCK
lint_select = ["E4", "E7", "E9", "F", "W"] # the rule set, explicit
typecheck_paths = ["origo"]
type_checker = "pyright"
typecheck_blocking = false
hotspot_limit = 20
```

Measuring is deliberately wider than gating. `tests/` lint is worth trending;
failing the build on a pre-existing finding there would force exactly the
unrelated cleanup this lane is not supposed to cause.

### Environment

| Variable | Purpose |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector base URL. Standard OTEL variable. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Auth for the Collector. Standard OTEL variable. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf`. |
| `CODE_HEALTH_ENDPOINT` | Optional direct document sink. |
| `CODE_HEALTH_TOKEN` | Bearer token for that sink. Never logged. |
| `CODE_HEALTH_REPOSITORY` | Repository name override. |
| `CODE_HEALTH_DEFAULT_BRANCH` | Which branch is canonical. Default `main`. |
| `CODE_HEALTH_AUTHORING_MODE` | Explicit provenance. See below. |
| `CODE_HEALTH_PR_LABELS` | Comma-separated PR labels. |
| `CODE_HEALTH_HUMAN_AUTHOR_IDS` | Stable internal IDs, not names or emails. |
| `CODE_HEALTH_REVIEW_APPROVALS` | Approval count, for review-effect analysis. |
| `MIRARUN_RUN_ID`, `MIRARUN_AGENT_NAME`, `MIRARUN_AGENT_PROVIDER`, `MIRARUN_MODEL`, `MIRARUN_AUTHORING_MODE` | Agent execution metadata from MiraRun. |

No proprietary exporter configuration exists, by design.

## Metric definitions

Definitions are also written into every artifact under `definitions`, so an old
snapshot stays interpretable without this file.

### The function set — the denominator behind every per-function number

`radon cc -j` returns a flat list per file containing **class, function and
method** blocks. Two traps:

1. Each method appears **twice** — at top level and nested under its class's
   `methods` — and each class block carries a complexity *derived from* its
   methods. Summing the flat list double-counts every method.
2. Closures appear **only** nested by default. `--show-closures` promotes them
   to top level under a qualified name (`https_open.build_conn`) *while also
   leaving them nested*, so recursing with the flag on double-counts closures.

Measured on this repository (24 files, radon 6.0.1):

| Walk | Blocks | Aggregate CC |
|---|---|---|
| Naive sum over the flat list | 102 | 484 |
| **Function set used here** | **92** | **440** |

The function set is: **top-level `function` and `method` blocks, with
`--show-closures` on, excluding `class` blocks, without recursing into
`closures`.** `summary.functions` is its cardinality, and it is the
denominator of `mean`, `high_complexity_fraction` and every bucket count.

### Complexity

| Field | Definition |
|---|---|
| `aggregate` | Sum of cyclomatic complexity over the function set. |
| `mean` | `aggregate / functions`. |
| `p50` / `p90` / `p95` | **Nearest-rank**: `index = ceil(q/100 × n)`, 1-based, clamped to `[1, n]`. |
| `max`, `min` | Extremes over the function set. |
| `functions_gt_10/15/20` | Strictly greater than the threshold. |
| `high_complexity_fraction` | `functions_gt_10 / functions`. |
| `density_per_kloc` | `aggregate / (source_loc / 1000)`. `null` below 200 source lines. |

**Why nearest-rank and not interpolation.** Cyclomatic complexity is a discrete
count. Interpolating between a function of 9 and one of 12 yields 10.8 — a
value no function has, which then moves whenever `n` changes even if no
function changed. Nearest-rank always returns an observed value, keeping a
percentile comparable across runs of different size.

### Lint

`lint.total` counts findings **under an explicitly declared rule selection**,
passed to ruff as `--select` and recorded in `lint.select`. It is never left to
ruff's defaults.

That is not a style preference — it is what makes the number a metric. Caught
on this lane's first CI run: the same commit measured **12 findings under ruff
0.15.8 and 153 under ruff 0.16.4**, because 0.16 widened its default selection
to include UP, I, RUF, BLE, SIM and TRY — and simultaneously dropped E402 from
the defaults, so the *blocking* count moved 12 → 10 as well. An unpinned
dependency float had silently redefined the metric by a factor of twelve and
changed which findings gate the build. With `--select` passed explicitly the
two versions agree exactly (13 findings, 12 blocking).

The default selection is `E4, E7, E9, F, W`: pyflakes, the syntax/runtime-error
subset of pycodestyle, and its warnings. It deliberately excludes E1/E2/E3/E5 —
whitespace and line length — which produce 534 E501 findings here and would
swamp the number with a signal about line width rather than code health.

Analyzer versions are **pinned exactly** in the `code-health` extra. `--select`
fixes the rule set; pinning closes the remaining drift, since a rule's
implementation can change between releases. Upgrading is a deliberate act and
appears in the series as a step change with the new version recorded beside it.

Changing `lint_select` makes deltas across the change `incomparable`, for the
same reason a type-checker swap does.

### LOC

From `radon raw`: `loc` is physical lines; `source_loc` is `sloc` — comments
and blank lines excluded. Both are stored; ratios use `source_loc`.

### Maintainability

`maintainability.mean_index` is the **unweighted mean** of radon's per-file MI.
Radon's MI is its own 0–100 rescaling, not the raw Coleman-Oman formula; the
two are not interchangeable across tools. A LOC-weighted variant would be a new
field, never a silent change to this one.

### Deltas

Computed against the previous successful default-branch snapshot.

* An absent baseline yields `null` for every delta — never `0`. Zero means
  "measured, and unchanged".
* `complexity_growth_per_loc = Δaggregate_cc / Δsource_loc`, suppressed when
  `|Δsource_loc| < 25`, where the ratio is dominated by its denominator.
* Deltas across a schema change, a definition change, a type-checker swap or a
  Python-version change are still reported but marked `incomparable` with a
  reason. Suppressing them would hide a real discontinuity in the series.

## Cardinality rules

A metric backend stores one series per distinct combination of name and
attribute values, and keeps it for the retention period whether or not it is
ever written again. The cost of an attribute is not one label — it is a
multiplier on every series it touches, paid forever.

**Permitted metric attributes** (`metrics.ALLOWED_METRIC_ATTRIBUTES`):

| Attribute | Bound |
|---|---|
| `vcs.repository.url.full` | One value per repository. |
| `code.health.ref_class` | Exactly two: `default_branch`, `other`. |
| `code.health.language` | One per analyzed language. |
| `code.health.tool` | One per configured analyzer. |

**Forbidden, and enforced at export time** by `assert_bounded_attributes`,
which raises rather than degrading quietly: commit SHA, branch name, PR id, CI
run id, file path, symbol name, agent run id, model identifier, end-user id.

This is forbidden:

```
code.health.function.complexity{commit_sha="…", file="…", function="…"}
```

### The resource trap

Resource attributes are **not** exempt. Most backends project them onto every
metric the resource produces — Prometheus turns them into target labels.
Putting `vcs.ref.head.revision` on the resource "because it isn't a metric
attribute" reintroduces exactly the explosion the attribute rule prevents.

So there are two resource shapes: `metric_resource_attributes()` (sparse:
`service.name`, `service.namespace`) for metrics, and
`context_resource_attributes()` (full run identity) for logs and traces.

Verified against the real SDK, on the wire (see `tests/code_health/test_otel_wire.py`
and the measurement below): the `/v1/metrics` payload contains **zero**
occurrences of the commit SHA, the branch name, or any file path.

### Where correlation lives instead

Per-commit and per-symbol detail is not lost, only routed. The artifact holds
everything; the `code.health.analysis` event holds the run-level record with
full identity; traces hold timing with full identity. Metrics join to those
through the bounded dimensions plus timestamp.

## Signals

**Metrics** — 20 gauges, listed in `metrics.METRICS`. Gauges rather than
counters: these are levels measured once per run, not monotonic totals, and
summing them across runs is meaningless. A metric whose value is `null` is
**not recorded at all** — a gap says "not measured", a zero says "measured, and
it was zero".

**Events** — one `code.health.analysis` log record per run carrying summary,
complexity, provenance, deltas, tool versions and a bounded hotspot list, plus
one `code.health.symbol` record per hotspot (capped, default 50). The full
symbol table stays in the artifact; a repository with 5,000 functions would
otherwise emit a multi-megabyte record on every push.

**Traces** — a `code_health.analysis` root span with one child per analyzer, so
analyzer duration and failure correlate with results. Adopts `TRACEPARENT` when
CI provides one, nesting under the pipeline's own trace.

### Payload discipline, measured

One full run of this repository (92 functions, 7 files) against a local OTLP
receiver:

| Signal | Requests | Bytes |
|---|---|---|
| `/v1/metrics` | 1 | 5,068 |
| `/v1/logs` | 1 | 10,315 |
| `/v1/traces` | 1 | 1,492 |

**3 requests, ~17 KB** — not 92 requests, one per function. Batching is done by
`BatchLogRecordProcessor` and a single metrics force-flush.

## Provenance

The point of this module is what it refuses to do. Authorship is **never**
inferred from commit-message text, co-author trailers, author names, or "this
looks agent-written". A heuristic that is 90% accurate produces a 10% mislabel
rate *correlated with the thing being measured*, which is worse than no data.

Populated only from sources explicit about themselves, in precedence order:

1. `workflow_input` — a `workflow_dispatch` input or explicit environment variable.
2. `mirarun` — agent execution metadata from the MiraRun control plane.
3. `pr_label` — `authoring:*` labels; trusted because applying one needs write access.

Modes: `human`, `human_assisted`, `agent_supervised`, `agent_autonomous`, `mixed`.

Rules that matter:

* **Unknown stays `null`.** Backfilling unknowns as `human` would bias every
  future comparison in exactly the direction the research question is about.
* **An invalid mode is rejected, not coerced** — a typo must not become a data point.
* **Conflicts are recorded, not resolved away.** If a label and a workflow input
  disagree, `conflict: true` and both appear in `declared_modes`; the
  disagreement is itself data.
* **A mixed change is representable** rather than forced into a binary.
* **`human_authors` are stable internal IDs**, not names or emails. The analyses
  need a pseudonymous key, not an identity, and a dataset accumulating personal
  data for years is a liability.
* `granularity` is `"change"` in v1 and says so. The schema is designed for
  commit / change / file / symbol provenance; only change level is populated
  reliably today, and claiming more would be fabrication.

## CI policy

**Blocking:** test failures; ruff findings in `lint_gate_paths` matching the
blocking selection (`F`, `E4`, `E7`, `E9`, plus syntax errors); analyzer
failure; existing security gates, unchanged.

**Measured, not blocking:** cyclomatic complexity, MI, Halstead, density,
hotspot counts, type errors (until a baseline reaches zero), any regression not
crossing an explicitly defined gate, and all telemetry export.

Complexity is deliberately not gated. Failing a build because a function
written in 2024 has CC 34 would teach everyone to distrust the lane. Ratchets
— "no new function above CC 15 without an exemption", "do not increase the
complexity of a touched function" — become possible once there is a baseline
series, and they belong in a later change.

### PR vs default branch

PR runs compare against the merge base, print deltas and notable symbol
movements, and are marked `canonical: false` — they observe a proposal that may
never land. Default-branch runs are the canonical historical series:
`canonical: true`, full artifact, full symbol and file records retained.

**Deduplication.** `run.observation_id` is `sha256` over `(schema_version,
repository, commit_sha, target_paths)`. Re-analyzing the same commit yields the
same id, so a backend can drop a duplicate ingestion; `ci.run_id` and
`run_attempt` are recorded separately so reruns stay *distinguishable* while
being *dedupable*.

## Endpoint contract

For whoever implements the receiving side. The producer is deliberately
independent of it.

```
POST $CODE_HEALTH_ENDPOINT
Content-Type: application/json
Content-Encoding: gzip
Authorization: Bearer $CODE_HEALTH_TOKEN     (omitted when unset)
Idempotency-Key: <run.observation_id>
User-Agent: code-health/0.1.0

<gzipped canonical snapshot>
```

Expected behaviour:

* **Any 2xx** is success. `202` is appropriate for async ingestion.
* **Deduplicate on `Idempotency-Key`**, which equals `run.observation_id` in the
  body. Repeated delivery of the same analysis is expected — reruns, replayed
  webhooks, a retried workflow — and must not create duplicate rows.
* **4xx other than 429 is not retried** — a malformed payload will be equally
  malformed on the third attempt. Return a body explaining the rejection; it is
  logged (truncated to 500 chars).
* **429 and 5xx are retried**, 3 attempts, backoff 1s → 2s, 15s timeout.
* The client never logs the token, and reads only the response body on error —
  never echoing request headers.
* Store `schema_version` and refuse to silently coerce across versions.

The `files` and `symbols` arrays are unbounded in principle (one entry per file
and per function). For this repository the gzipped payload is a few tens of KB;
a large monorepo will be larger, so size limits should be explicit rather than
discovered.

## SonarQube Community Build — evaluation

**Recommendation: do not add it to v1. Keep the integration point documented
and revisit when a second language arrives.**

Supplementary, never authoritative: if SonarQube disagrees with radon, ruff or
pyright, the dedicated tools and their raw measurements win, and Sonar values
would be namespaced (`sonar.*`) rather than overwriting any field above.

Reasons to wait:

1. **Licensing is genuinely mixed, and this is the strongest reason.** Since
   2024-11-29 the SonarQube Community Build platform is LGPLv3, but the
   **bundled analyzers are under the Sonar Source-Available License v1
   (SSALv1)** — source-available, *not* OSI open source. Every other tool in
   this lane (ruff MIT, radon MIT, pyright MIT, mypy MIT, bandit Apache-2.0,
   OSV-Scanner Apache-2.0) is OSI-licensed. Adopting SSALv1 into the
   measurement path is a licensing decision that deserves its own conversation,
   not a side effect of a telemetry change.
2. **Operational cost is real.** Community Build needs a server plus a database
   and becomes infrastructure that must be patched, backed up and kept
   available. The current lane has no runtime dependency at all beyond a
   Collector it treats as optional.
3. **Its complexity metric is not our complexity metric.** Sonar increments per
   control-flow split with a minimum of 1 per function — similar in spirit to
   radon but not identical in the constructs counted, and Sonar's headline
   maintainability figure is *cognitive complexity* plus a remediation-effort
   model, which is a different quantity again. Mixing them into one series
   without a mapping study would corrupt exactly the longitudinal comparability
   this schema exists to protect.
4. **Marginal signal today.** For a single-language Python repository, ruff plus
   pyright plus bandit plus semgrep already cover the lint/type/SAST surface.

Reasons it may earn its place later: cross-language normalization when the
frontend repos are added; Sonar's own duplication and cognitive-complexity
metrics, which nothing here currently measures; and a UI for people who will not
read JSON.

**The integration point when it happens:** a `tools/code_health/analyzers/sonar.py`
adapter reading the web API, writing a `sonar` section with namespaced keys and
its own `status`, plus `sonar.*` metric names registered in `metrics.py` with
their own bounded attributes. Nothing in the schema needs to change to
accommodate it — which is the test that it is genuinely supplementary.

## Current hotspots

From the baseline run (`origo` package only, 92 functions, aggregate CC 440,
density 266.5/kLOC, MI 57.1):

| CC | Location | Symbol |
|---|---|---|
| 34 | `origo/endpoints.py:545` | `authorize` |
| 29 | `origo/endpoints.py:683` | `token` |
| 26 | `origo/storage.py:267` | `OAuthStorage._cleanup_expired` |
| 19 | `origo/provider.py:121` | `OAuthProvider.__init__` |
| 18 | `origo/middleware.py:69` | `OAuthMiddleware.__call__` |
| 14 | `origo/endpoints.py:385` | `register` |
| 12 | `origo/endpoints.py:198` | `_fetch_client_metadata_document` |
| 11 | `origo/endpoints.py:151` | `_SafeHTTPSConnection.connect` |

`authorize` and `token` are the OAuth flow's two branchiest endpoints, which is
where the protocol's error handling concentrates — high complexity there is
expected rather than alarming on its own. **These are recorded, not actioned.**
Deciding what to refactor is a separate change, made from a trend rather than
from one reading.

## Statistical integrity

* Raw counts are preserved alongside every derived metric, so a future reader
  who disagrees with a definition can recompute from the artifact.
* Tool versions are recorded per analyzer. The version parser skips pyright's
  "a new version is available" notice, which would otherwise be stored *as* the
  version.
* `typing.errors` depends on the resolved Python environment, not only the code:
  the same pyright over the same code reports 49 errors with dependencies
  installed and 53 without, the difference being `reportMissingImports`. So
  `typing.import_errors` and `typing.errors_excluding_imports` are stored
  separately and `typing.environment` records the interpreter.
* Timestamps are UTC, second resolution, `Z`-suffixed.
* No rounding before storage; rounding happens only in `report.py`.
* Missing ≠ zero, and analyzer failure ≠ no findings, everywhere. Each
  analyzer-backed section carries `status ∈ {ok, error, unavailable, skipped}`.
* Schema changes that alter meaning require a `SCHEMA_VERSION` bump; the test
  suite pins the version, the top-level key tuple, and every definition
  parameter, so a silent redefinition fails CI.
