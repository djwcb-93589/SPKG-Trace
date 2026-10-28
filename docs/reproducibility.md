# Reproducibility

## Scope

This source tree supports execution of the backend method. It does not include
private logs, previously generated results, an evaluation leaderboard, or model
weights. The synthetic authentication example demonstrates the input interface;
it must not be treated as a reproduction of a paper experiment.

## Record an experiment

Record the source revision; Python and dependency versions; dataset provenance,
license, split, and input hash; POI and relation schemas; prompt hashes; model
name and revision; server/runtime version; context and output budgets; temperature;
seed; concurrency; and whether checkpoints or cached responses were reused.

Use `requirements.lock.txt` with Python 3.13 for the pinned dependency baseline.
The pipeline's sample seed controls sampling, not all model/server nondeterminism.
Runs with the same nominal configuration can still differ.

Start a new run for changed experimental conditions. `--resume` is for compatible
checkpoints, not a substitute for an independent cold run. Preserve the manifest,
quality report, inference usage, extraction errors, and review traces privately.
These artifacts can include raw log text and local paths.

## Validation layers

1. Run unit tests for evidence contracts, bounded revisions, schema rules, and
   provider request behavior. Provider tests use a local mock HTTP service.
2. Validate the actual endpoint with `check-llm` and `check-llm --generate`.
3. Run the synthetic example, then inspect extracted fields and graph coverage.
4. Evaluate research datasets using independent ground truth and a documented
   scoring protocol. A successful exit code is not an accuracy metric.
5. Validate graph import separately against a disposable compatible database.

No benchmark metrics are asserted by this repository. Dataset access, annotation
protocols, experimental configurations, and paper-specific evaluation scripts
must be supplied before claiming reproduction of reported research results.
