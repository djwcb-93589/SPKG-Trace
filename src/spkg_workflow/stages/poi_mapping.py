from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

import yaml

from spkg_workflow.config import WorkflowSettings
from spkg_workflow.contracts import (
    ContractError,
    FieldMapping,
    TemplateFieldMapping,
    TemplateFieldSemantics,
    TemplateRecord,
)
from spkg_workflow.providers import OpenAICompatibleClient
from spkg_workflow.stages.field_semantics import format_template_input


class PoiMappingError(RuntimeError):
    """Raised when a POI schema or field mapping violates the closed set."""


@dataclass(frozen=True, slots=True)
class PoiSchema:
    schema_id: str
    source_path: str
    definitions: dict[str, str]

    @property
    def fields(self) -> tuple[str, ...]:
        return tuple(self.definitions)


def load_poi_schema(path: str | Path, *, schema_id: str | None = None) -> PoiSchema:
    source = Path(path).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"POI schema does not exist: {source}")
    definitions: dict[str, str] = {}
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        for line_number, row in enumerate(csv.reader(handle), start=1):
            if not row or not any(cell.strip() for cell in row):
                continue
            if len(row) < 2:
                raise PoiMappingError(
                    f"POI schema {source} line {line_number} needs field and definition"
                )
            name = row[0].strip()
            definition = row[1].strip()
            if not name or not definition:
                raise PoiMappingError(
                    f"POI schema {source} line {line_number} contains an empty value"
                )
            if name in definitions:
                raise PoiMappingError(f"Duplicate POI field {name!r} in {source}")
            definitions[name] = definition
    if not definitions:
        raise PoiMappingError(f"POI schema is empty: {source}")
    return PoiSchema(
        schema_id=schema_id or source.stem,
        source_path=str(source),
        definitions=definitions,
    )


def parse_mapping_lines(
    completion: str,
    *,
    source_fields: Iterable[str],
    canonical_fields: Iterable[str],
    forbidden_targets: Iterable[str] = (),
) -> tuple[dict[str, str | None], tuple[str, ...]]:
    sources = tuple(source_fields)
    source_set = set(sources)
    canonical_lookup = {field.lower(): field for field in canonical_fields}
    forbidden = {field.lower() for field in forbidden_targets}
    parsed: dict[str, str | None] = {}
    duplicate_sources: set[str] = set()
    warnings: list[str] = []

    for raw_line in completion.splitlines():
        line = raw_line.strip()
        if not line or "->" not in line:
            continue
        source, raw_target = (part.strip() for part in line.split("->", 1))
        if source not in source_set:
            warnings.append(f"unknown_source_ignored:{source}")
            continue
        if source in parsed:
            duplicate_sources.add(source)
            continue
        normalized_target = raw_target.strip(" .,'\"").lower()
        if normalized_target == "none":
            parsed[source] = None
        elif normalized_target in forbidden:
            parsed[source] = None
            warnings.append(f"forbidden_target_rejected:{source}:{normalized_target}")
        elif normalized_target in canonical_lookup:
            parsed[source] = canonical_lookup[normalized_target]
        else:
            parsed[source] = None
            warnings.append(f"unknown_target_rejected:{source}:{normalized_target}")

    for source in duplicate_sources:
        parsed[source] = None
        warnings.append(f"duplicate_source_mapping_rejected:{source}")
    for source in sources:
        if source not in parsed:
            parsed[source] = None
            warnings.append(f"missing_source_mapping_defaulted_to_none:{source}")
    return parsed, tuple(warnings)


def load_mapping_overrides(path: str | Path | None) -> dict[str, dict[str, str | None]]:
    """Load optional explicit mappings keyed by ``default`` or template ID."""
    if path is None:
        return {}
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"Mapping override file does not exist: {source}")
    payload = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise PoiMappingError("Mapping override root must be an object")
    result: dict[str, dict[str, str | None]] = {}
    for scope, raw_mapping in payload.items():
        if not isinstance(raw_mapping, dict):
            raise PoiMappingError(f"Override scope {scope!r} must be an object")
        result[str(scope)] = {
            str(source_field): (
                None if target is None or str(target).upper() == "NONE" else str(target)
            )
            for source_field, target in raw_mapping.items()
        }
    return result


def _apply_overrides(
    mappings: dict[str, str | None],
    *,
    template_id: str,
    overrides: Mapping[str, Mapping[str, str | None]],
    canonical_fields: set[str],
    forbidden_targets: set[str],
) -> tuple[dict[str, str | None], set[str]]:
    overridden: set[str] = set()
    for scope in ("default", template_id):
        for source, target in overrides.get(scope, {}).items():
            if source not in mappings:
                raise PoiMappingError(
                    f"Override refers to unknown source field {source!r} in {scope!r}"
                )
            if target is not None:
                if target in forbidden_targets:
                    raise PoiMappingError(
                        f"Override maps {source!r} to forbidden field {target!r}"
                    )
                if target not in canonical_fields:
                    raise PoiMappingError(
                        f"Override maps {source!r} outside the POI schema: {target!r}"
                    )
            mappings[source] = target
            overridden.add(source)
    return mappings, overridden


def map_template_fields(
    template: TemplateRecord,
    semantics: TemplateFieldSemantics,
    poi_schema: PoiSchema,
    *,
    settings: WorkflowSettings,
    client: OpenAICompatibleClient | None = None,
    overrides: Mapping[str, Mapping[str, str | None]] | None = None,
) -> TemplateFieldMapping:
    if template.template_id != semantics.template_id:
        raise ContractError(
            f"Template/semantics ID mismatch: {template.template_id} != {semantics.template_id}"
        )
    raw = settings.raw.get("poi_mapping") or {}
    forbidden = {str(item) for item in raw.get("forbid_targets", ["log_source"])}
    allowed_definitions = {
        name: definition
        for name, definition in poi_schema.definitions.items()
        if name not in forbidden
    }
    canonical_lines = [
        f"- {name}: {definition}" for name, definition in allowed_definitions.items()
    ]
    canonical_lines.append("- NONE: No suitable canonical mapping for strict alignment.")
    source_lines = [
        f"- {field.source_field}: {field.definition}" for field in semantics.fields
    ]

    prompt_path = settings.resolve_path(raw.get("prompt", "prompts/poi_mapping.txt"))
    if not prompt_path.is_file():
        raise FileNotFoundError(f"POI mapping prompt does not exist: {prompt_path}")
    prompt = prompt_path.read_text(encoding="utf-8").format_map(
        {
            "canonical_fields": "\n".join(canonical_lines),
            "source_fields": "\n".join(source_lines),
            "input_text": format_template_input(template),
        }
    )
    selected_client = client or OpenAICompatibleClient(settings.provider)
    source_names = [field.source_field for field in semantics.fields]
    coverage = semantics.metadata.get("poi_coverage", {})
    feedback = ""
    for attempt in range(int(raw.get("validation_retries", 2)) + 1):
        completion = selected_client.generate(
            [{"role": "user", "content": prompt + "\nUpstream POI coverage assessment:\n"
              + json.dumps(coverage, ensure_ascii=False) + "\n" + feedback}],
            stage="poi_mapping", max_tokens=int(raw.get("max_tokens", 4096)),
            temperature=float(raw.get("temperature", 0.0)))
        parsed, warnings = parse_mapping_lines(completion, source_fields=source_names,
                                               canonical_fields=allowed_definitions, forbidden_targets=forbidden)
        parsed, overridden = _apply_overrides(parsed, template_id=template.template_id,
            overrides=overrides or {}, canonical_fields=set(allowed_definitions), forbidden_targets=forbidden)
        conflicts = []
        for target, item in coverage.items():
            if target not in allowed_definitions:
                continue
            sources = item.get("source_fields", [])
            if any(source in overridden for source in sources):
                continue
            if item["status"] == "available" and not any(parsed.get(s) == target for s in sources):
                conflicts.append(f"Available POI {target} has declared sources {sources} but is not mapped")
            if item["status"] == "unavailable" and any(v == target for k, v in parsed.items() if k not in overridden):
                conflicts.append(f"Unavailable POI {target} must not receive an unrelated source field")
        if not conflicts and not warnings:
            break
        feedback = "Regenerate every mapping; resolve these coverage/format conflicts: " + str(conflicts + list(warnings))
    else:
        raise PoiMappingError(feedback)

    mappings: list[FieldMapping] = []
    for field in semantics.fields:
        target = parsed[field.source_field]
        status = (
            "override"
            if field.source_field in overridden
            else "mapped"
            if target is not None
            else "unmapped"
        )
        mappings.append(
            FieldMapping(
                source_field=field.source_field,
                source_definition=field.definition,
                canonical_field=target,
                canonical_definition=(
                    allowed_definitions[target] if target is not None else None
                ),
                status=status,
                rationale=(
                    "explicit_override"
                    if status == "override"
                    else "llm_closed_set_mapping"
                    if status == "mapped"
                    else "none_or_rejected_mapping"
                ),
            )
        )
    return TemplateFieldMapping(
        dataset_id=template.dataset_id,
        template_id=template.template_id,
        poi_schema_id=poi_schema.schema_id,
        mappings=tuple(mappings),
        warnings=warnings,
        revision=semantics.revision,
        metadata={"model": settings.provider.models["poi_mapping"],
                  "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                  "semantics_revision": semantics.revision, "validation_retries": attempt},
    )


def map_catalog_fields(
    templates: Iterable[TemplateRecord],
    semantics_records: Iterable[TemplateFieldSemantics],
    poi_schema: PoiSchema,
    *,
    settings: WorkflowSettings,
    overrides: Mapping[str, Mapping[str, str | None]] | None = None,
    client: OpenAICompatibleClient | None = None,
) -> tuple[TemplateFieldMapping, ...]:
    template_by_id = {item.template_id: item for item in templates}
    semantics_by_id = {item.template_id: item for item in semantics_records}
    if template_by_id.keys() != semantics_by_id.keys():
        missing_semantics = sorted(template_by_id.keys() - semantics_by_id.keys())
        missing_templates = sorted(semantics_by_id.keys() - template_by_id.keys())
        raise ContractError(
            "Template/semantics catalogs differ: "
            f"missing_semantics={missing_semantics}, missing_templates={missing_templates}"
        )
    client = client or OpenAICompatibleClient(settings.provider)
    return tuple(
        map_template_fields(
            template_by_id[template_id],
            semantics_by_id[template_id],
            poi_schema,
            settings=settings,
            client=client,
            overrides=overrides,
        )
        for template_id in sorted(template_by_id)
    )
