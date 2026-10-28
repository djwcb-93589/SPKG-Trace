from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Callable

from spkg_workflow.config import WorkflowSettings
from spkg_workflow.contracts import (ParsedLogRecord, RawLogRecord, TemplateFieldMapping,
    TemplateFieldSemantics, read_jsonl, write_jsonl)
from spkg_workflow.dataset_config import DatasetSpec
from spkg_workflow.librelog import LibreLogOptions, parse_log_file
from spkg_workflow.librelog.adapter import LibreLogRun, write_compatibility_csv
from spkg_workflow.providers import OpenAICompatibleClient
from spkg_workflow.stages.field_semantics import extract_catalog_field_semantics
from spkg_workflow.stages.knowledge_package import KnowledgePackageResult, build_knowledge_package, sha256_file
from spkg_workflow.stages.llm_parameters import digest_json, save_payload
from spkg_workflow.stages.parameter_extraction import extract_parameters, write_parameter_csv
from spkg_workflow.stages.poi_mapping import load_mapping_overrides, load_poi_schema, map_catalog_fields
from spkg_workflow.stages.template_sampling import build_template_catalog

ProgressCallback = Callable[[str], None]
STAGE_DIRS = ("01_librelog", "02_templates", "03_field_semantics", "04_poi_mapping",
              "05_parameters", "06_knowledge_package")
RUN_FILES = ("run_report.md", "run_state.json", "run_config.json", "llm_usage.json",
             "quality_report.json", "acceptance_report.json", "test_console.log")


@dataclass(frozen=True, slots=True)
class WorkflowResult:
    dataset_id: str
    result_dir: Path
    knowledge_package: KnowledgePackageResult


def _archive_result(root: Path) -> Path | None:
    targets = [root / name for name in (*STAGE_DIRS, *RUN_FILES) if (root / name).exists()]
    if not targets:
        return None
    archive = root / "_history" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    for source in targets:
        if source.is_symlink() or source.resolve().parent != root.resolve():
            raise ValueError("Refusing to archive a result outside this dataset directory")
    archive.mkdir(parents=True, exist_ok=False)
    for source in targets:
        destination = archive / source.name
        if root.resolve() not in destination.resolve().parents:
            raise ValueError("Archive destination must remain inside the dataset result directory")
        source.rename(destination)
    return archive


def run_workflow(dataset: DatasetSpec, *, settings: WorkflowSettings,
                 progress: ProgressCallback | None = None, resume: bool = False) -> WorkflowResult:
    notify = progress or (lambda _: None)
    base = settings.resolve_path((settings.raw.get("project") or {}).get("results_dir", "results")).resolve()
    root = (base / dataset.dataset_id).resolve()
    if root.parent != base:
        raise ValueError("Dataset result must be a direct child of results_dir")
    root.mkdir(parents=True, exist_ok=True)
    if not resume:
        archive = _archive_result(root)
        if archive:
            notify(f"已有结果已归档：{archive}")
    dirs = {name: root / name for name in STAGE_DIRS}
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    state_path = root / "run_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if resume and state_path.exists() else {}
    state.setdefault("run_id", datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    state["status"] = "running"
    state.pop("error_type", None)
    save_payload(state_path, state)
    client = OpenAICompatibleClient(settings.provider)
    usage_path = root / "llm_usage.json"
    previous_usage = json.loads(usage_path.read_text(encoding="utf-8")) if resume and usage_path.exists() else {}
    try:
        return _execute(dataset, settings, notify, resume, root, dirs, state, client, previous_usage)
    except Exception as exc:
        state["status"] = "failed"
        state["error_type"] = type(exc).__name__
        raise
    finally:
        save_payload(state_path, state)
        _save_usage(usage_path, client, previous_usage)


def _save_usage(path, client, previous_usage):
    usage = client.usage_summary()
    calls = previous_usage.get("calls", []) + usage["calls"]
    by_stage = {}
    for call in calls:
        totals = by_stage.setdefault(call["stage"], {"responses": 0, "errors": 0, "prompt_tokens": 0, "completion_tokens": 0})
        totals["responses" if call["status"] == "response" else "errors"] += 1
        totals["prompt_tokens"] += call.get("prompt_tokens", 0)
        totals["completion_tokens"] += call.get("completion_tokens", 0)
    save_payload(path, {"calls": calls, "by_stage": by_stage})


def _execute(dataset, settings, notify, resume, root, dirs, state, client, previous_usage) -> WorkflowResult:
    state_path = root / "run_state.json"
    poi = load_poi_schema(dataset.poi_schema, schema_id=dataset.family)
    package_settings = settings.raw.get("knowledge_package") or {}
    if package_settings.get("prepare_neo4j_import", False):
        # Reject unusable graph rules before spending any LLM quota.
        import yaml
        from spkg_workflow.stages.neo4j_export import compile_schema
        policy_path = settings.resolve_path(package_settings.get("graph_export_policy", "configs/graph_export.yaml"))
        compile_schema(dataset.poi_schema, dataset.relation_schema, yaml.safe_load(policy_path.read_text(encoding="utf-8")))
    overrides = load_mapping_overrides(dataset.mapping_overrides)
    raw_hash = sha256_file(dataset.raw_log)
    provenance = {"run_id": state["run_id"], "raw_log_sha256": raw_hash,
                  "source_path": str(dataset.raw_log), "models": settings.provider.models,
                  "provider_request": settings.provider.request_signature(),
                  "provider_base_url": settings.provider.base_url, "extractor": "llm",
                  "prompt_sha256": {stage: sha256_file(settings.resolve_path(settings.raw[stage]["prompt"]))
                                    for stage in ("field_semantics", "poi_mapping", "parameter_extraction")}}
    provenance["code_sha256"] = {p.relative_to(settings.root).as_posix(): sha256_file(p)
                                for p in sorted((settings.root / "src" / "spkg_workflow").rglob("*.py"))}
    if (settings.raw.get("parameter_extraction") or {}).get("semantic_review"):
        provenance["prompt_sha256"]["parameter_review"] = sha256_file(settings.resolve_path(settings.raw["parameter_extraction"]["review_prompt"]))
    if (settings.raw.get("parameter_extraction") or {}).get("catalog_review"):
        provenance["prompt_sha256"]["catalog_review"] = sha256_file(settings.resolve_path(settings.raw["parameter_extraction"]["catalog_review_prompt"]))
    save_payload(root / "run_config.json", {"provenance": provenance,
                 "parameter_extraction": settings.raw.get("parameter_extraction", {})})
    raw_path = dirs["01_librelog"] / "raw_logs.jsonl"
    parsed_path = dirs["01_librelog"] / "parsed_logs.jsonl"
    signature = digest_json({"raw": raw_hash, "source_path": str(dataset.raw_log), "librelog": settings.raw.get("librelog"),
                            "project": settings.raw.get("project"), "model": settings.provider.models["librelog"],
                            "provider": settings.provider.request_signature(),
                            "code": {k: v for k, v in provenance["code_sha256"].items() if "/librelog/" in k}})
    can_reuse = resume and state.get("librelog_input") == signature and all(
        p.is_file() and sha256_file(p) == state.get(p.name) for p in (raw_path, parsed_path))
    notify("1/6 LibreLog：复用校验通过的检查点" if can_reuse else "1/6 LibreLog：原始日志生成模板正则")
    if can_reuse:
        run = LibreLogRun(tuple(read_jsonl(raw_path, RawLogRecord)), tuple(read_jsonl(parsed_path, ParsedLogRecord)))
    else:
        run = parse_log_file(dataset.raw_log, dataset_id=dataset.dataset_id, settings=settings,
                             options=LibreLogOptions.from_settings(settings), client=client)
        write_jsonl(raw_path, run.raw_records)
        write_jsonl(parsed_path, run.parsed_records)
        write_compatibility_csv(dirs["01_librelog"] / "parsed_logs.csv", run.parsed_records)
        state.update({"librelog_input": signature, raw_path.name: sha256_file(raw_path), parsed_path.name: sha256_file(parsed_path)})
        save_payload(state_path, state)
    notify("2/6 模板样本：建立模板目录")
    project = settings.raw.get("project") or {}
    templates = build_template_catalog(run.parsed_records, sample_size=int(project.get("sample_size", 3)),
                                       sample_seed=int(project.get("sample_seed", 42)))
    template_path = dirs["02_templates"] / "templates.jsonl"
    write_jsonl(template_path, templates)
    semantics_path = dirs["03_field_semantics"] / "field_semantics.jsonl"
    mapping_path = dirs["04_poi_mapping"] / "field_mappings.jsonl"
    signature = digest_json({"templates": [t.to_dict() for t in templates], "poi": poi.definitions,
        "prompts": {k: v for k, v in provenance["prompt_sha256"].items() if k in {"field_semantics", "poi_mapping"}},
        "settings": {k: settings.raw.get(k) for k in ("field_semantics", "poi_mapping")},
        "models": {k: settings.provider.models[k] for k in ("field_semantics", "poi_mapping")},
        "provider": settings.provider.request_signature(), "overrides": overrides,
        "code": {k: v for k, v in provenance["code_sha256"].items() if k.endswith(("field_semantics.py", "poi_mapping.py"))}})
    can_reuse = resume and state.get("catalog_input") == signature and all(
        p.is_file() and sha256_file(p) == state.get(p.name) for p in (semantics_path, mapping_path))
    notify("3/6 字段语义：" + ("复用检查点" if can_reuse else "LLM 描述原子字段及语义"))
    if can_reuse:
        semantics = tuple(read_jsonl(semantics_path, TemplateFieldSemantics))
    else:
        semantics = extract_catalog_field_semantics(templates, settings=settings,
                                                    poi_definitions=poi.definitions, client=client)
        write_jsonl(semantics_path, semantics)
    notify("4/6 POI 映射：" + ("复用检查点" if can_reuse else "LLM 对齐字段角色"))
    if can_reuse:
        mappings = tuple(read_jsonl(mapping_path, TemplateFieldMapping))
    else:
        mappings = map_catalog_fields(templates, semantics, poi, settings=settings, overrides=overrides, client=client)
        write_jsonl(mapping_path, mappings)
    state.update({"catalog_input": signature, semantics_path.name: sha256_file(semantics_path),
                  mapping_path.name: sha256_file(mapping_path)})
    save_payload(state_path, state)
    notify("5/6 参数抽取：LLM 逐日志取值、证据校验和有界修正")
    batch = extract_parameters(run.parsed_records, templates, semantics, mappings,
        settings=settings, poi_schema=poi, output_dir=dirs["05_parameters"], log_source=dataset.log_source,
        family=dataset.family, overrides=overrides, client=client, progress=notify)
    write_jsonl(semantics_path, batch.semantics)
    write_jsonl(mapping_path, batch.mappings)
    state.update({semantics_path.name: sha256_file(semantics_path), mapping_path.name: sha256_file(mapping_path)})
    save_payload(state_path, state)
    params = dirs["05_parameters"] / "parameters.jsonl"
    params_csv = dirs["05_parameters"] / "parameters.csv"
    errors = dirs["05_parameters"] / "extraction_errors.jsonl"
    write_jsonl(params, batch.records)
    write_parameter_csv(params_csv, batch.records, canonical_fields=poi.fields)
    write_jsonl(errors, batch.errors)
    statuses = Counter(r.status for r in batch.records)
    quality = {"processing_status": "complete" if statuses.get("ok", 0) == len(run.raw_records) else "partial",
               "semantic_accuracy_verified": False, "record_statuses": dict(statuses),
               "nonempty_canonical_fields": {name: sum(r.canonical_parameters[name] is not None for r in batch.records) for name in poi.fields},
               "unmapped_source_values": sum(len(r.metadata.get("unmapped_source_fields", [])) for r in batch.records),
               "extraction_metrics": batch.metrics,
               "note": "Evidence/contract checks do not establish semantic correctness. Non-ok CSV rows are quarantined."}
    save_payload(root / "quality_report.json", quality)
    counts = {"raw_logs": len(run.raw_records), "parsed_logs": len(run.parsed_records),
              "templates": len(templates), "field_semantics": len(batch.semantics),
              "field_mappings": len(batch.mappings), "parameters": len(batch.records),
              "extraction_errors": len(batch.errors)}
    notify("6/6 知识包：保存参数、证据、Schema、质量状态和离线 Neo4j 导入文件")
    _save_usage(root / "llm_usage.json", client, previous_usage)
    revisions = {"revisions": [json.loads(p.read_text(encoding="utf-8"))
                  for p in sorted((dirs["05_parameters"] / "upstream_revisions").rglob("*.json"))]}
    revisions["catalog_reviews"] = [json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(dirs["05_parameters"].glob("catalog_review_*.json"))]
    save_payload(dirs["05_parameters"] / "upstream_revisions.json", revisions)
    package = build_knowledge_package(settings=settings, package_dir=dirs["06_knowledge_package"],
        package_id=f"{dataset.dataset_id}-{state['run_id']}", dataset_id=dataset.dataset_id,
        source_files=(str(dataset.raw_log),), artifact_paths={
            "templates": template_path, "field_semantics": semantics_path, "field_mappings": mapping_path,
            "parameters_jsonl": params, "parameters_csv": params_csv, "extraction_errors": errors,
            "quality_report": root / "quality_report.json", "run_config": root / "run_config.json",
            "llm_usage": root / "llm_usage.json", "extraction_attempts": dirs["05_parameters"] / "attempts.jsonl",
            "upstream_revisions": dirs["05_parameters"] / "upstream_revisions.json",
            "extraction_metrics": dirs["05_parameters"] / "metrics.json"},
        record_counts=counts, poi_schema_path=dataset.poi_schema, relation_schema_path=dataset.relation_schema,
        poi_schema_id=poi.schema_id, relation_schema_id=f"{dataset.family}_relations",
        quality=quality, provenance=provenance)
    report = [f"# {dataset.dataset_id} LLM 参数抽取运行报告", "",
              f"运行标识：{state['run_id']}", "", f"处理状态：{quality['processing_status']}",
              "", "参数由 LLM 从原文抽取，业务规则抽取器未进入主流程。", "",
              "| 项目 | 数量 |", "| --- | ---: |",
              *[f"| {k} | {v} |" for k, v in counts.items()], "",
              f"逐行状态：{dict(statuses)}", "",
              "参数 JSONL 保留每个字段的原文证据及 literal/normalized/derived/absent/uncertain 状态。",
              "非 ok 行在 CSV 中保留行号与原文，标准参数置空，防止旧构图器误用。", "",
              "本报告的完整性和证据检查不等于语义正确率；独立验收结果另存 acceptance_report.json。",
              "Neo4j 导入文件按配置离线生成；未连接数据库或执行 Neo4j 写入。", "",
              "固定结果目录：" + str(root), ""]
    (root / "run_report.md").write_text("\n".join(report), encoding="utf-8")
    state["status"] = quality["processing_status"]
    notify(f"完成：{package.manifest_path}，状态={state['status']}")
    return WorkflowResult(dataset.dataset_id, root, package)
