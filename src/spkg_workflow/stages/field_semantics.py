from __future__ import annotations

import hashlib
import json
import re
from typing import Iterable, Mapping

from spkg_workflow.config import WorkflowSettings
from spkg_workflow.contracts import ContractError, FieldSemantic, TemplateFieldSemantics, TemplateRecord
from spkg_workflow.providers import OpenAICompatibleClient
from spkg_workflow.providers.openai_compatible import ProviderRequestError

FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]*$")


class FieldSemanticsError(ContractError):
    pass


def format_template_input(template: TemplateRecord) -> str:
    return json.dumps({"template": template.regex_template, "samples": list(template.samples)}, ensure_ascii=False)


def parse_field_semantics(payload: dict, template: TemplateRecord) -> tuple[FieldSemantic, ...]:
    items = payload.get("fields")
    if not isinstance(items, list) or not items:
        raise FieldSemanticsError("fields must be a non-empty list")
    fields = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise FieldSemanticsError("Each field must be an object")
        name = item.get("source_field")
        definition = item.get("definition")
        kind = item.get("value_kind", "literal")
        examples = item.get("examples", [])
        if not isinstance(name, str) or not FIELD_NAME.fullmatch(name) or name in seen:
            raise FieldSemanticsError("Source field names must be unique snake_case identifiers")
        if not isinstance(definition, str) or not definition.strip():
            raise FieldSemanticsError(f"Missing definition for {name}")
        if kind not in {"literal", "normalized", "derived"}:
            raise FieldSemanticsError(f"Invalid value_kind for {name}")
        if not isinstance(examples, list) or any(not isinstance(v, str) or not v for v in examples):
            raise FieldSemanticsError(f"Invalid examples for {name}")
        if kind == "literal" and any(not any(v in sample for sample in template.samples) for v in examples):
            raise FieldSemanticsError(f"Example for {name} is absent from all samples")
        nullable = item.get("nullable", True)
        if not isinstance(nullable, bool):
            raise FieldSemanticsError(f"nullable must be boolean for {name}")
        allowed_values = item.get("allowed_values", [])
        if not isinstance(allowed_values, list) or any(not isinstance(v, str) or not v for v in allowed_values):
            raise FieldSemanticsError(f"Invalid allowed_values for {name}")
        if kind == "derived" and not allowed_values:
            raise FieldSemanticsError(f"Derived field {name} needs a stable allowed_values vocabulary")
        fields.append(FieldSemantic(source_field=name, definition=definition.strip(),
                                    examples=tuple(examples), extraction_kind="llm",
                                    nullable=nullable, value_kind=kind, allowed_values=tuple(allowed_values)))
        seen.add(name)
    return tuple(fields)


def extract_template_field_semantics(
    template: TemplateRecord, *, settings: WorkflowSettings,
    poi_definitions: Mapping[str, str] | None = None,
    client: OpenAICompatibleClient | None = None,
    feedback: list[dict] | None = None, revision: int = 1,
    catalog_context: list[dict] | None = None,
) -> TemplateFieldSemantics:
    config = settings.raw.get("field_semantics") or {}
    prompt_path = settings.resolve_path(config.get("prompt", "prompts/field_semantics.txt"))
    prompt = prompt_path.read_text(encoding="utf-8")
    request = {"template": template.regex_template, "samples": list(template.samples),
               "poi_definitions": dict(poi_definitions or {}), "upstream_feedback": feedback or [],
               "related_templates_for_role_context_only": catalog_context or []}
    selected_client = client or OpenAICompatibleClient(settings.provider)
    validation_feedback = ""
    for attempt in range(int(config.get("validation_retries", 2)) + 1):
        try:
            payload = selected_client.generate_json(
                [{"role": "system", "content": prompt},
                 {"role": "user", "content": json.dumps(request, ensure_ascii=False)},
                 *([{"role": "user", "content": validation_feedback}] if validation_feedback else [])],
                stage="field_semantics", max_tokens=int(config.get("max_tokens", 4096)),
                temperature=float(config.get("temperature", 0.0)))
            if config.get("semantic_review", True):
                payload = selected_client.generate_json(
                    [{"role": "system", "content": prompt + "\nYou are an independent reviewer of candidate_fields. "
                      "Return the complete corrected JSON. Check every field's role against explicit wording in "
                      "the current and related samples. Prefer explicit initiator/target wording over a guessed "
                      "interpretation of shorthand. When related messages contain the same identities/process, "
                      "their roles must be consistent; do not reverse the two members of a compound pair. "
                      "Compare available POIs against declared source fields. One source can map to only one POI; "
                      "do not claim one source covers two targets. Either define distinct role-specific source "
                      "fields or mark the less specific POI unavailable. Never invent absent account names from "
                      "numeric IDs. Event action describes what happened, outcome describes its result. "
                      "Review finite vocabularies and evidence before returning all fields and coverage."},
                     {"role": "user", "content": json.dumps({**request, "candidate_fields": payload}, ensure_ascii=False)}],
                    stage="field_semantics", max_tokens=int(config.get("max_tokens", 4096)),
                    temperature=float(config.get("temperature", 0.0)))
            fields = parse_field_semantics(payload, template)
            coverage = payload.get("poi_coverage", {})
            if poi_definitions:
                if not isinstance(coverage, dict) or set(coverage) != set(poi_definitions):
                    raise FieldSemanticsError("poi_coverage must explicitly cover every supplied POI")
                field_names = {f.source_field for f in fields}
                claimed = {}
                for name, item in coverage.items():
                    if not isinstance(item, dict) or item.get("status") not in {"available", "unavailable"}:
                        raise FieldSemanticsError(f"Invalid POI coverage for {name}")
                    sources = item.get("source_fields", [])
                    if not isinstance(sources, list) or any(s not in field_names for s in sources):
                        raise FieldSemanticsError(f"Coverage refers to unknown source fields for {name}")
                    if (item["status"] == "available") != bool(sources) or not item.get("reason"):
                        raise FieldSemanticsError(f"Coverage status/sources/reason inconsistent for {name}")
                    for source in sources:
                        if source in claimed:
                            raise FieldSemanticsError(f"Source {source} cannot cover both {claimed[source]} and {name}; define separate atomic fields or mark the less specific POI unavailable")
                        claimed[source] = name
            return TemplateFieldSemantics(
                dataset_id=template.dataset_id, template_id=template.template_id,
                regex_pattern=template.regex_pattern, fields=fields, revision=revision,
                metadata={"model": settings.provider.models["field_semantics"],
                          "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                          "validation_retries": attempt, "extraction_strategy": "llm",
                          "poi_coverage": coverage})
        except (ContractError, ProviderRequestError, ValueError) as exc:
            validation_feedback = f"Regenerate the full JSON. Validation failed: {exc}"
    raise FieldSemanticsError(validation_feedback)


def extract_catalog_field_semantics(
    templates: Iterable[TemplateRecord], *, settings: WorkflowSettings,
    poi_definitions: Mapping[str, str] | None = None,
    client: OpenAICompatibleClient | None = None,
) -> tuple[TemplateFieldSemantics, ...]:
    selected_client = client or OpenAICompatibleClient(settings.provider)
    templates = tuple(templates)
    context = [{"template_id": t.template_id, "template": t.regex_template, "samples": list(t.samples)}
               for t in templates[:32]]
    return tuple(extract_template_field_semantics(t, settings=settings,
                 poi_definitions=poi_definitions, client=selected_client, catalog_context=context) for t in templates)
