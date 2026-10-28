# Configuration

## Model interface

`configs/pipeline.yaml` selects the provider, prompt files, extraction/review
budgets, and graph-export policy. The default `vllm` backend uses the configured
OpenAI-compatible `/v1/models` and `/v1/chat/completions` endpoints. Replace the
model placeholder with an actual served model ID.

| Environment variable | Meaning |
| --- | --- |
| `SPKG_VLLM_BASE_URL` | API base URL ending in `/v1` |
| `SPKG_VLLM_MODEL` | Shared served model ID for all inference stages |
| `SPKG_VLLM_AUTH_REQUIRED` | Whether a nonempty service credential is required |
| `SPKG_VLLM_API_KEY` | Credential; never tracked in version control |
| `SPKG_VLLM_TIMEOUT_SECONDS` | Request timeout |
| `SPKG_VLLM_MAX_WORKERS` | Parameter-extraction concurrency |
| `SPKG_VLLM_JSON_MODE` | `prompt` or `json_object` |
| `SPKG_VLLM_CHAT_TEMPLATE_KWARGS` | Optional supported boolean thinking switches |

Existing environment variables take precedence over `.env.local`. The `vllm`
backend does not fall back to cloud endpoints or inherit unrelated cloud keys.
Its unauthenticated SDK placeholder is `EMPTY`, not a real credential.

`prompt` mode requests JSON through the prompt without sending `response_format`.
Use `json_object` only when supported by the endpoint. Thinking switches depend
on the model template; leave them unset unless verified. Only final answer content
is parsed. Empty answers, incomplete reasoning blocks, and length-truncated
responses fail validation. Increase budgets only within the server context limit.

The semantic, mapping, and parameter stages share the mapping-stage temperature
and output budget. LibreLog has a separate output budget. The model ID is shared
across all stages in `vllm` mode. No model weights are distributed here.

## Schemas and identity

POI CSV (no header):

```csv
client,Client account explicitly mentioned in the event
service,Target service identifier
action,Action category: login or logout; leave absent without supporting evidence
```

Relation CSV:

```csv
subject_type,subject_id_source,predicate,object_type,object_id_source,edge_properties,condition,subject_scope,object_scope
Customer,client,USES,Application,service,action,"action in (login,logout)",dataset,dataset
```

The first seven columns are required. `subject_scope` and `object_scope` are
optional. Quote cells containing commas according to CSV syntax. Fields and
graph identifiers must use safe letter/underscore-prefixed identifiers.

Scopes are `event`, `dataset`, `host`, and `global`. `host` falls back to dataset
scope when the host is missing. All scopes are isolated within a graph snapshot;
`global` does not merge entities across packages. A new type defaults to `event`.
Explicit CSV scopes override built-in scopes; conflicting declarations for the
same type are rejected. Other built-in identity settings remain effective.

Conditions support `not null`, `is null`, `=`, `==`, `!=`, `in (...)`, and `AND`.
Values are matched exactly. OR, arbitrary expressions, and nested conditions are
unsupported. Built-in `indicates` aliases remain supported; define new sets
directly with `in (...)` rather than relying on inferred alias meanings.

POI/schema compatibility is checked before inference when graph preparation is
enabled. The effective compiled rules and default-scope warnings are included in
the graph package. Passing these checks does not establish semantic correctness.
