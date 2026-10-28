from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
from threading import Lock
from typing import Callable, Iterable, Mapping

from spkg_workflow.config import WorkflowSettings
from spkg_workflow.contracts import (
    ContractError, ExtractedRecord, ExtractionError, ParsedLogRecord,
    TemplateFieldMapping, TemplateFieldSemantics, TemplateRecord,
)
from spkg_workflow.providers import OpenAICompatibleClient
from spkg_workflow.providers.openai_compatible import ProviderRequestError
from spkg_workflow.stages.field_semantics import extract_template_field_semantics
from spkg_workflow.stages.poi_mapping import PoiSchema, map_template_fields
from spkg_workflow.stages.template_sampling import template_id_for_record


def digest_json(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def save_payload(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


@dataclass(frozen=True, slots=True)
class ParameterExtractionBatch:
    records: tuple[ExtractedRecord, ...]
    errors: tuple[ExtractionError, ...]
    semantics: tuple[TemplateFieldSemantics, ...]
    mappings: tuple[TemplateFieldMapping, ...]
    metrics: dict


class LLMParameterExtractor:
    """All business values come from the model; no family registry or value fallback."""

    def __init__(self, *, settings: WorkflowSettings, poi_schema: PoiSchema,
                 output_dir: Path, client: OpenAICompatibleClient | None = None):
        self.settings = settings
        self.poi = poi_schema
        self.config = settings.raw.get("parameter_extraction") or {}
        self.client = client or OpenAICompatibleClient(settings.provider)
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir = output_dir.parent / "_cache" / "parameters"
        self.prompt = settings.resolve_path(self.config.get("prompt", "prompts/parameter_extraction.txt")).read_text(encoding="utf-8")
        self.prompt_hash = hashlib.sha256(self.prompt.encode()).hexdigest()
        self.review_prompt = settings.resolve_path(self.config.get("review_prompt", "prompts/parameter_review.txt")).read_text(encoding="utf-8") if self.config.get("semantic_review", False) else ""
        self.lock = Lock()
        self.metrics = {"batches": 0, "cache_hits": 0, "model_requests": 0,
                        "validation_failures": 0, "upstream_revisions": 0}

    def _increment(self, name: str, count: int = 1) -> None:
        with self.lock:
            self.metrics[name] += count

    def _journal(self, data: dict) -> None:
        with self.lock:
            with (self.output_dir / "attempts.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(data, ensure_ascii=False) + "\n")

    def _request(self, records: list[ParsedLogRecord], template: TemplateRecord,
                 semantics: TemplateFieldSemantics, mapping: TemplateFieldMapping) -> dict:
        targets = {item.source_field: item.canonical_field for item in mapping.mappings}
        return {
            "template_id": template.template_id, "template": template.regex_template,
            "fields": [{"source_field": f.source_field, "definition": f.definition,
                        "value_kind": f.value_kind, "nullable": f.nullable,
                        "allowed_values": list(f.allowed_values),
                        "canonical_field": targets[f.source_field]} for f in semantics.fields],
            "poi_definitions": self.poi.definitions,
            "role_context": semantics.metadata.get("upstream_feedback", []),
            "records": [{"line_id": r.line_id, "original_content": r.original_content} for r in records],
        }

    def _batch(self, records: list[ParsedLogRecord], template: TemplateRecord,
               semantics: TemplateFieldSemantics, mapping: TemplateFieldMapping,
               log_source: str, family: str) -> list[ExtractedRecord]:
        from spkg_workflow.stages.parameter_validation import validate_response

        request = self._request(records, template, semantics, mapping)
        identity = {"engine": "llm-values-v2", "request": request,
                    "semantics": semantics.to_dict(), "mapping": mapping.to_dict(),
                    "provider": self.settings.provider.request_signature(),
                    "model": self.settings.provider.models["parameter_extraction"],
                    "prompt_sha256": self.prompt_hash, "temperature": self.config.get("temperature", 0.0),
                    "review_prompt_sha256": hashlib.sha256(self.review_prompt.encode()).hexdigest(),
                    "max_tokens": self.config.get("max_tokens", 4096),
                    "disable_thinking": self.settings.provider.disable_thinking}
        key = digest_json(identity)
        cache_file = self.cache_dir / (key + ".json")
        cached = None
        if self.config.get("cache", True) and cache_file.is_file():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                if cached.get("key") != key:
                    cached = None
            except (OSError, ValueError):
                cached = None
        feedback = ""
        max_attempts = int(self.config.get("validation_retries", 2)) + 1
        self._increment("batches")
        for attempt in range(max_attempts):
            from_cache = cached is not None
            payload = None
            try:
                if from_cache:
                    payload = cached["payload"]
                    cached = None
                else:
                    self._increment("model_requests")
                    payload = self.client.generate_json(
                        [{"role": "system", "content": self.prompt},
                         {"role": "user", "content": json.dumps(request, ensure_ascii=False)},
                         *([{"role": "user", "content": feedback}] if feedback else [])],
                        stage="parameter_extraction", max_tokens=int(self.config.get("max_tokens", 4096)),
                        temperature=float(self.config.get("temperature", 0.0)))
                result = validate_response(payload, records, semantics, mapping, self.poi)
                if self.review_prompt and not from_cache:
                    self._journal({"request_sha256": key, "line_ids": [r.line_id for r in records],
                                   "validation": "draft", "response": payload})
                    self._increment("model_requests")
                    payload = self.client.generate_json(
                        [{"role": "system", "content": self.review_prompt},
                         {"role": "user", "content": json.dumps({"input": request, "candidate": payload}, ensure_ascii=False)}],
                        stage="parameter_extraction", max_tokens=int(self.config.get("max_tokens", 4096)),
                        temperature=float(self.config.get("temperature", 0.0)))
                    result = validate_response(payload, records, semantics, mapping, self.poi)
                provenance = {"model": self.settings.provider.models["parameter_extraction"],
                              "prompt_sha256": self.prompt_hash, "request_sha256": key,
                              "semantic_review": bool(self.review_prompt),
                              "review_prompt_sha256": hashlib.sha256(self.review_prompt.encode()).hexdigest(),
                              "semantics_revision": semantics.revision, "mapping_revision": mapping.revision,
                              "semantics_sha256": digest_json(semantics.to_dict()),
                              "mapping_sha256": digest_json(mapping.to_dict()), "cache_hit": from_cache,
                              "attempts": attempt + 1, "extractor": "llm", "family": family,
                              "log_source": log_source}
                result = [replace(r, metadata={**r.metadata, **provenance}) for r in result]
                self._journal({"request_sha256": key, "template_id": template.template_id,
                               "line_ids": [r.line_id for r in records], "attempt": attempt + 1,
                               "cache_hit": from_cache, "validation": "accepted", "response": payload})
                if from_cache:
                    self._increment("cache_hits")
                elif self.config.get("cache", True):
                    save_payload(cache_file, {"key": key, "payload": payload})
                return result
            except (ContractError, ProviderRequestError, ValueError, KeyError) as exc:
                self._increment("validation_failures")
                feedback = f"Return the complete JSON for exactly the supplied records. Validation error: {exc}"
                self._journal({"request_sha256": key, "template_id": template.template_id,
                               "line_ids": [r.line_id for r in records], "attempt": attempt + 1,
                               "cache_hit": from_cache, "validation": "rejected", "error": str(exc),
                               "response": payload})
        return [ExtractedRecord(
            dataset_id=r.dataset_id, line_id=r.line_id, template_id=template.template_id,
            timestamp=r.timestamp, original_content=r.original_content,
            source_parameters={f.source_field: None for f in semantics.fields},
            canonical_parameters={f: None for f in self.poi.fields}, status="error",
            metadata={"extractor": "llm", "log_source": log_source, "family": family,
                      "source_path": r.source_path, "failure": feedback,
                      "request_sha256": key, "attempts": max_attempts,
                      "semantics_revision": semantics.revision, "mapping_revision": mapping.revision,
                      "model": self.settings.provider.models["parameter_extraction"],
                      "prompt_sha256": self.prompt_hash}) for r in records]

    def _run(self, rows: list[ParsedLogRecord], templates: dict, semantics: dict, mappings: dict,
             log_source: str, family: str, progress: Callable[[str], None]) -> list[ExtractedRecord]:
        grouped: dict[str, list] = {}
        for row in rows:
            grouped.setdefault(template_id_for_record(row), []).append(row)
        size = int(self.config.get("batch_size", 1))
        workers = int(self.config.get("max_workers", 8))
        if size < 1 or workers < 1:
            raise ContractError("batch_size and max_workers must be positive")
        result = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            pending = []
            for tid, group in grouped.items():
                for start in range(0, len(group), size):
                    pending.append(executor.submit(self._batch, group[start:start + size], templates[tid],
                                   semantics[tid], mappings[tid], log_source, family))
            for future in as_completed(pending):
                result.extend(future.result())
                if len(result) % 10 == 0 or len(result) == len(rows):
                    progress(f"LLM 参数抽取 {len(result)}/{len(rows)}")
        return result

    def extract(self, parsed_records: Iterable[ParsedLogRecord], templates: Iterable[TemplateRecord],
                semantics_records: Iterable[TemplateFieldSemantics], mappings: Iterable[TemplateFieldMapping],
                *, log_source: str, family: str = "", overrides: Mapping | None = None,
                progress: Callable[[str], None] | None = None) -> ParameterExtractionBatch:
        notify = progress or (lambda _: None)
        rows = sorted(parsed_records, key=lambda r: r.line_id)
        if len({(r.dataset_id, r.line_id) for r in rows}) != len(rows):
            raise ContractError("Duplicate input record identity")
        catalogs = []
        for items in (templates, semantics_records, mappings):
            catalog = {}
            for item in items:
                if item.template_id in catalog:
                    raise ContractError("Duplicate template identity in catalog")
                catalog[item.template_id] = item
            catalogs.append(catalog)
        ts, ss, ms = catalogs
        if not (set(ts) == set(ss) == set(ms) == {template_id_for_record(r) for r in rows}):
            raise ContractError("Rows and all three catalogs must cover the same template IDs")
        for tid in ts:
            if [f.source_field for f in ss[tid].fields] != [m.source_field for m in ms[tid].mappings]:
                raise ContractError(f"Field/mapping catalog mismatch: {tid}")
            if any(m.canonical_field is not None and m.canonical_field not in self.poi.fields for m in ms[tid].mappings):
                raise ContractError(f"Mapping outside POI: {tid}")
        result = self._run(rows, ts, ss, ms, log_source, family, notify)
        max_revisions = int(self.config.get("upstream_retries", 1))
        for round_index in range(max_revisions + 1):
            if self.config.get("catalog_review", False):
                from spkg_workflow.stages.catalog_review import review_parameter_catalog
                notify(f"LLM 跨模板参数一致性复核 round={round_index}")
                result = review_parameter_catalog(result, ss, self.poi, settings=self.settings,
                    client=self.client, output_dir=self.output_dir, round_index=round_index)
            affected = {r.template_id for r in result if r.metadata.get("upstream_issues")}
            if not affected or round_index == max_revisions:
                break
            repaired = set()
            for tid in sorted(affected):
                issues = [r for r in result if r.template_id == tid and r.metadata.get("upstream_issues")]
                feedback = [{"line_id": r.line_id, "original_content": r.original_content,
                             "issues": r.metadata["upstream_issues"]} for r in issues[:8]]
                revision = ss[tid].revision + 1
                revision_dir = self.output_dir / "upstream_revisions" / tid / str(revision)
                save_payload(revision_dir / "before.json", {"semantics": ss[tid].to_dict(),
                             "mapping": ms[tid].to_dict(), "feedback": feedback})
                notify(f"字段表反馈修正 {tid} revision={revision}")
                augmented = replace(ts[tid], samples=tuple(dict.fromkeys(
                    [*ts[tid].samples, *(r.original_content for r in issues[:8])])) )
                try:
                    new_semantics = extract_template_field_semantics(augmented, settings=self.settings,
                        poi_definitions=self.poi.definitions, client=self.client, feedback=feedback, revision=revision,
                        catalog_context=[{"template": t.regex_template, "samples": list(t.samples)} for t in list(ts.values())[:32]])
                    # Preserve evidence-backed role corrections through the repair
                    # loop. Generic definitions alone can lose the disambiguating
                    # context which originally exposed the mapping error.
                    new_semantics = replace(new_semantics, metadata={**new_semantics.metadata,
                        "upstream_feedback": feedback})
                    new_mapping = map_template_fields(augmented, new_semantics, self.poi,
                        settings=self.settings, client=self.client, overrides=overrides)
                    save_payload(revision_dir / "after.json", {"semantics": new_semantics.to_dict(),
                                 "mapping": new_mapping.to_dict()})
                    ss[tid], ms[tid] = new_semantics, new_mapping
                    repaired.add(tid)
                    self._increment("upstream_revisions")
                except (ContractError, ProviderRequestError, ValueError) as exc:
                    self._journal({"template_id": tid, "revision": revision, "repair_error": str(exc)})
            if not repaired:
                break
            new_result = self._run([r for r in rows if template_id_for_record(r) in repaired],
                                  ts, ss, ms, log_source, family, notify)
            result = [r for r in result if r.template_id not in repaired] + new_result
        unresolved_templates = {r.template_id for r in result if r.metadata.get("upstream_issues")}
        result = [replace(r, status="uncertain", metadata={**r.metadata,
            "failure": "Unresolved field semantics in this template; all its records are quarantined"})
            if r.template_id in unresolved_templates and r.status == "ok" else r for r in result]
        result.sort(key=lambda r: r.line_id)
        errors = tuple(ExtractionError(dataset_id=r.dataset_id, line_id=r.line_id,
            template_id=r.template_id, stage="parameter_extraction",
            code="llm_validation_failed" if r.status == "error" else "unresolved_semantics",
            message=str(r.metadata.get("failure") or r.metadata.get("upstream_issues") or "Uncertain fields"),
            original_content=r.original_content) for r in result if r.status != "ok")
        save_payload(self.output_dir / "metrics.json", self.metrics)
        return ParameterExtractionBatch(tuple(result), errors, tuple(ss.values()), tuple(ms.values()), dict(self.metrics))
