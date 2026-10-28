# Data contracts

Typed JSON/JSONL records use `contract_version: "1.1"` and an explicit
`record_type`; readers also accept version 1.0. Cache, usage, and quality reports
are auxiliary artifacts rather than typed stage records.

| Record type | Principal traceability fields |
| --- | --- |
| `raw_log` | `dataset_id`, `line_id`, `source_path`, `original_content` |
| `parsed_log` | Input identity, `event_id`, `regex_template`, `regex_pattern` |
| `template` | `template_id`, `samples`, `sample_line_ids`, `occurrence_count` |
| `template_field_semantics` | `source_field`, `definition`, `value_kind`, `revision` |
| `template_field_mapping` | `source_field`, `canonical_field`, `status` |
| `extracted_record` | `source_parameters`, `canonical_parameters`, `field_evidence`, `status` |
| `knowledge_package_manifest` | Artifact paths, hashes, counts, schemas, and provenance |

Records are joined by identifiers and field names, never by list position.
`dataset_id` plus `line_id` identifies an input record. Templates are identified
from the dataset and final regex, retaining associated intermediate event IDs.

New semantic fields use `extraction_kind: llm`; the parameter engine does not
execute legacy capture bindings or dataset-family extractors. Unmapped canonical
fields are explicitly null. Original input text is retained.

Evidence states distinguish literal, normalized, derived, absent, and uncertain
values. Literal evidence must come from the same input record. Derived fields
require an upstream declaration, supporting evidence, and permitted values.
Missing or uncertain values are null. Bounded validation and revision may produce
error or uncertain records rather than silently inventing values.

Non-ok records retain diagnostics in JSONL; their canonical CSV values are blank
to avoid accidental use by status-unaware consumers. Unresolved template-level
issues quarantine all affected records, not only reviewed samples.

The manifest distinguishes processing completeness from semantic verification.
Graph-preparation status is under `quality.neo4j_import`. Legacy graph/database
execution flags remain false because offline artifact generation does not write
to a live database.
