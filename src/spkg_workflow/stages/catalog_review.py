from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

from spkg_workflow.contracts import ContractError
from spkg_workflow.providers import ProviderRequestError
from spkg_workflow.stages.llm_parameters import save_payload


def review_parameter_catalog(records, semantics, poi, *, settings, client, output_dir: Path, round_index: int):
    """LLM cross-record consistency review; never assigns a business value in code."""
    config = settings.raw.get("parameter_extraction") or {}
    prompt = settings.resolve_path(config.get("catalog_review_prompt", "prompts/catalog_review.txt")).read_text(encoding="utf-8")
    grouped = {}
    for record in records:
        grouped.setdefault(record.template_id, []).append(record)
    samples = []
    ordered = sorted(records, key=lambda r: r.line_id)
    positions = {r.line_id: i for i, r in enumerate(ordered)}
    for tid, group in grouped.items():
        # Keep rare templates in full and three deterministic representatives of
        # common ones. This is a sample audit, not a claim to inspect every value.
        chosen = group if len(group) <= 4 else [group[0], group[len(group) // 2], group[-1]]
        context = {}
        for record in chosen:
            index = positions[record.line_id]
            for nearby in ordered[max(0, index - 2):index + 3]:
                context[nearby.line_id] = nearby.original_content
        # Do not supply potentially incorrect source-field definitions: this audit
        # must interpret original evidence independently of upstream assumptions.
        samples.append({"template_id": tid,
                        "records": [{"line_id": r.line_id, "original_content": r.original_content,
                                     "canonical_parameters": r.canonical_parameters} for r in chosen],
                        "context_records": [{"line_id": k, "original_content": v}
                                            for k, v in sorted(context.items())]})
    reviewed = []
    all_issues = []
    for sample in samples:
        payload = _review_sample(sample, poi, prompt, config, client, records)
        reviewed.append({"template_id": sample["template_id"], **payload})
        all_issues.extend(payload["issues"])
    save_payload(output_dir / f"catalog_review_{round_index}.json",
                 {"scope": "representative rows with nearby original context", "reviews": reviewed,
                  "issues": all_issues})
    issues_by_id = {}
    for issue in all_issues:
        issues_by_id.setdefault(issue["line_id"], []).append(issue)
    return [replace(r, status="uncertain", metadata={**r.metadata,
             "upstream_issues": [*r.metadata.get("upstream_issues", []), *issues_by_id[r.line_id]]})
            if r.line_id in issues_by_id else r for r in records]


def _review_sample(sample, poi, prompt, config, client, records):
    by_id = {r.line_id: r for r in records}
    target_ids = {r["line_id"] for r in sample["records"]}
    supplied_ids = target_ids | {r["line_id"] for r in sample["context_records"]}
    feedback = ""
    for attempt in range(int(config.get("validation_retries", 2)) + 1):
        try:
            payload = client.generate_json(
                [{"role": "system", "content": prompt},
                 {"role": "user", "content": json.dumps({"poi_definitions": poi.definitions,
                    **sample}, ensure_ascii=False)},
                 *([{"role": "user", "content": feedback}] if feedback else [])],
                stage="parameter_extraction", max_tokens=int(config.get("max_tokens", 4096)),
                temperature=float(config.get("temperature", 0.0)))
            if not isinstance(payload, dict):
                raise ContractError("Catalog audit must be an object")
            assessments = payload.get("assessments")
            if (not isinstance(assessments, list) or len(assessments) != len(target_ids)
                    or any(not isinstance(a, dict) or type(a.get("line_id")) is not int
                           or not isinstance(a.get("reason"), str) or not a["reason"].strip()
                           for a in assessments)
                    or {a["line_id"] for a in assessments} != target_ids):
                raise ContractError("Assess every target record exactly once with a nonempty reason")
            if not isinstance(payload.get("issues"), list) or len(payload["issues"]) > 16:
                raise ContractError("Catalog audit requires an issues list, at most 16")
            issues_by_id = {}
            for issue in payload["issues"]:
                if not isinstance(issue, dict) or type(issue.get("line_id")) is not int or issue["line_id"] not in target_ids:
                    raise ContractError("Catalog audit references an unknown record")
                if issue.get("kind") not in {"mapping_conflict", "missing_field"} or not isinstance(issue.get("message"), str) or not issue["message"].strip():
                    raise ContractError("Catalog audit requires a supported kind and correction message")
                quote = issue.get("evidence")
                if not isinstance(quote, str) or not quote or quote not in by_id[issue["line_id"]].original_content:
                    raise ContractError("Catalog audit issue must quote its own original record")
                related = issue.get("related_evidence", [])
                if not isinstance(related, list):
                    raise ContractError("related_evidence must be a list")
                for support in related:
                    if not isinstance(support, dict) or type(support.get("line_id")) is not int or support["line_id"] not in supplied_ids:
                        raise ContractError("Unknown supporting record")
                    quote = support.get("evidence")
                    if not isinstance(quote, str) or not quote or quote not in by_id[support["line_id"]].original_content:
                        raise ContractError("Supporting evidence must quote the referenced original log")
                issues_by_id.setdefault(issue["line_id"], []).append(issue)
            return payload
        except (ContractError, ProviderRequestError, ValueError) as exc:
            feedback = "Regenerate the complete audit JSON: " + str(exc)
    raise ContractError("Catalog consistency audit failed: " + feedback)
