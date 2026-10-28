# SPKG-Trace: A Semantic Provenance Knowledge Graph for Heterogeneous-Log Analysis and Interpretable Attack Traceback

**Authors:** Yan Wangᵃ˒ᵇ˒ᶜ, Pengyu Liuᵃ, Zeyu Qianᵃ˒ᶜ, Xiaoze Liuᵇ˒ᶜ,
Wentao Liᵇ˒ᶜ, Quijian Lvᵇ˒ᶜ, Ruijie Daiᵃ˒ᶜ, Ziyang Yuᵇ˒* and Guokun Xuᵇ

**Paper:**

**License:**

## Overview

SPKG is a research implementation that converts raw logs into structured parameters
and graph-ready artifacts. It combines LibreLog template induction, LLM-based field
semantics, alignment to a predefined POI field inventory, and per-record parameter
extraction with evidence validation. A deterministic stage materializes nodes and
relationships according to a user-specified relation schema.

This release contains the log-processing and graph-preparation backend. It does
not include a separate attack-traceback query engine or claim to reproduce all
experiments described by the paper title.

The workflow requires a field inventory and relation schema; it is not schema-free.
No per-record annotations are required by the inference pipeline. This does not
imply that outputs are error-free or that semantic correctness is automatically verified.

## Method overview

```text
Raw logs → LibreLog templates → Field semantics → POI alignment
         → Parameter extraction and review → Knowledge package
                                          → Offline Neo4j import artifacts
```

1. **Template induction:** group log records and induce regular-expression templates.
2. **Field semantics:** describe reusable source fields and their semantic roles.
3. **POI alignment:** map source fields to a closed inventory of canonical fields.
4. **Parameter extraction:** extract values from each original record, retaining
   evidence and explicit absent/uncertain states.
5. **Bounded revision:** review extraction and representative samples, revise
   upstream definitions when necessary, and retry affected records within configured limits.
6. **Graph preparation:** preserve events and evidence, apply explicit relation
   rules, and produce independently verifiable import files without contacting a database.

## Repository structure

```text
configs/           Pipeline settings, POI inventories, relation schemas
examples/          Synthetic input only
prompts/           Prompts used by the inference and review stages
src/spkg_workflow/  Backend workflow and command-line interface
tests/             Contract, extraction, provider, and graph-export tests
docs/              Method, configuration, data contracts, and reproduction notes
scripts/           Public-content checks
```

The repository contains no browser interface, private datasets, model weights,
credentials, or precomputed experimental results. The synthetic example is an API
smoke-test input, not a benchmark or evidence of paper-level performance.

## Installation

Python **3.13** is the dependency-lock baseline. The package metadata permits
Python 3.10+, but the locked dependency set should be installed with Python 3.13.
An existing OpenAI-compatible model endpoint is required for inference. The
workflow itself does not serve a model or require a GPU.

```sh
python3.13 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock.txt
python -m pip install --no-build-isolation --no-deps -e .
python -m pip check
```

Keep this repository's configuration and prompt files alongside the source tree;
the documented workflow uses an editable installation.

## Quick start

Copy `.env.example` to `.env.local` and set the endpoint and actual served model ID:

```dotenv
SPKG_VLLM_BASE_URL=http://127.0.0.1:8000/v1
SPKG_VLLM_MODEL=your-served-model-id
SPKG_VLLM_AUTH_REQUIRED=false
SPKG_VLLM_API_KEY=
```

For authenticated endpoints, set `SPKG_VLLM_AUTH_REQUIRED=true` and provide the key
only through a local environment file or environment variable. Never commit it.
The endpoint must expose compatible model-listing and chat-completion APIs.

```sh
spkg-workflow list-datasets
spkg-workflow check-llm
spkg-workflow check-llm --generate
spkg-workflow run synthetic_auth
```

`check-llm --generate` sends a small synthetic request. `run` sends the selected log
records to the configured endpoint and may incur inference charges. Endpoint
compatibility does not establish extraction quality. See [configuration](docs/configuration.md)
for model, context, reasoning, and concurrency settings.

## Using your own logs

Create a dataset YAML under `configs/datasets/`, following `synthetic_auth.yaml`.
Set `raw_log`, `poi_schema`, and `relation_schema` to the intended files. Relative
paths are resolved from the repository root. Store private logs under `data/`,
which is excluded from version control.

POI CSVs have no header and contain a field name and semantic description per row.
Relation CSVs specify typed endpoints, source fields, predicates, properties, and
explicit conditions. New node types need no Python registration; their default
identity scope is one event. Optional CSV scope columns control merging. See
[schema configuration](docs/configuration.md#schemas-and-identity).

```sh
spkg-workflow run my_dataset
spkg-workflow run my_dataset --resume
```

Resume reuses only compatible checkpoints and validated cached responses. A run
without `--resume` archives existing outputs. Exit code `0` denotes complete
processing, `3` partial processing, and `2` a workflow error.

## Outputs

All outputs are written under `results/<dataset_id>/`:

```text
01_librelog/          Parsed records and template associations
02_templates/        Template inventory and representative samples
03_field_semantics/  Source fields and semantic definitions
04_poi_mapping/      Canonical field mappings
05_parameters/       Values, evidence, errors, and review traces
06_knowledge_package/
  manifest.json      Artifact inventory, hashes, and provenance
  neo4j/             Nodes, relationships, validation, and standalone importer
```

Graph export is offline. It does not write to Neo4j. The generated importer first
validates the package; database writes require an explicit `--apply` flag. See
[graph artifacts](docs/graph-artifacts.md). Outputs retain original logs and may
contain personal or operationally sensitive information; do not publish them
without a separate review.

## Testing and reproducibility

```sh
python -m unittest discover -s tests -v
python scripts/check_public_tree.py
```

Tests use synthetic fixtures and mocked or loopback model responses. They do not
require a real model or database and do not measure semantic accuracy. Full model
inference, benchmark reproduction, and real database import are separate checks.
See [reproducibility](docs/reproducibility.md) for the information to record.

## Limitations

- LLM extraction and self-review can share systematic errors. Evidence and schema
  checks are not independent verification of semantic roles.
- Representative-sample review is not exhaustive evaluation.
- Process and session nodes are event-scoped by default; cross-record entity
  resolution is not inferred.
- Timestamps are preserved without inventing a year or time zone.
- Relation conditions use a finite grammar, not arbitrary code or natural-language reasoning.
- Private evaluation datasets and numerical paper results are not included.

## Citation and licensing

The paper title and author list are provided above. The paper link and project
license are intentionally left unspecified. A machine-readable citation will be
added when the publication metadata is available. No benchmark result or new
license grant is implied. Existing third-party notices are preserved; see
[third-party notices](THIRD_PARTY_NOTICES.md) for attribution and the scope of
the included LibreLog-derived components.
