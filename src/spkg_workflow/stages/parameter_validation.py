from __future__ import annotations

from spkg_workflow.contracts import ContractError, ExtractedRecord


def validate_response(payload, records, semantics, mapping, poi_schema) -> list[ExtractedRecord]:
    """Validate evidence and shape; never infer values or repair a business role in code."""
    if not isinstance(payload, dict) or not isinstance(payload.get("records"), list):
        raise ContractError("Response must be an object with records list")
    expected = {r.line_id: r for r in records}
    seen = set()
    results = []
    semantic_fields = {f.source_field: f for f in semantics.fields}
    targets = {m.source_field: m.canonical_field for m in mapping.mappings}
    for item in payload["records"]:
        if not isinstance(item, dict):
            raise ContractError("Response record must be an object")
        line_id = item.get("line_id")
        if type(line_id) is not int or line_id not in expected or line_id in seen:
            raise ContractError("Wrong, duplicate or non-integer line_id")
        seen.add(line_id)
        record = expected[line_id]
        fields = item.get("fields")
        if not isinstance(fields, dict) or set(fields) != set(semantic_fields):
            missing = sorted(set(semantic_fields) - set(fields or {})) if isinstance(fields, dict) else sorted(semantic_fields)
            raise ContractError(f"line_id={line_id}: source fields differ from catalog; missing={missing}")
        source = {}
        evidence_table = {}
        canonical = {name: None for name in poi_schema.fields}
        warnings = []
        for name, field in semantic_fields.items():
            entry = fields[name]
            if not isinstance(entry, dict) or "value" not in entry or "status" not in entry:
                raise ContractError(f"line_id={line_id} field={name}: value and status required")
            value, status = entry["value"], entry["status"]
            quote = entry.get("evidence")
            raw = entry.get("raw_value")
            reason = entry.get("reason", "")
            if value is not None and (not isinstance(value, str) or not value):
                raise ContractError(f"line_id={line_id} field={name}: value must be non-empty string or null")
            if not isinstance(reason, str):
                raise ContractError(f"line_id={line_id} field={name}: invalid reason")
            if quote is not None and (not isinstance(quote, str) or not quote or quote not in record.original_content):
                raise ContractError(f"line_id={line_id} field={name}: evidence is not an exact quote from this log")
            if status in {"absent", "uncertain"}:
                if value is not None or raw is not None:
                    raise ContractError(f"line_id={line_id} field={name}: absent/uncertain must have null value")
                if status == "absent" and quote is not None:
                    raise ContractError(f"line_id={line_id} field={name}: absent must have null evidence")
                if status == "uncertain":
                    if not reason.strip():
                        raise ContractError(f"line_id={line_id} field={name}: uncertainty requires a reason")
                    warnings.append(f"uncertain:{name}")
            elif status in {"literal", "normalized", "derived"}:
                if value is None or quote is None:
                    raise ContractError(f"line_id={line_id} field={name}: non-null value and evidence required")
                if status == "literal":
                    if value not in quote or (raw is not None and raw != value):
                        raise ContractError(f"line_id={line_id} field={name}: literal value must occur in evidence")
                    raw = value
                else:
                    if field.value_kind != status or not reason.strip():
                        raise ContractError(f"line_id={line_id} field={name}: {status} not authorized by field definition or reason missing")
                    if status == "normalized" and (not isinstance(raw, str) or not raw or raw not in quote):
                        raise ContractError(f"line_id={line_id} field={name}: normalization requires an evidenced raw_value")
                    if raw is not None and (not isinstance(raw, str) or raw not in quote):
                        raise ContractError(f"line_id={line_id} field={name}: raw_value is not in evidence")
            else:
                raise ContractError(f"line_id={line_id} field={name}: invalid status")
            source[name] = value
            if value is not None and field.allowed_values and value not in field.allowed_values:
                raise ContractError(f"line_id={line_id} field={name}: value outside declared vocabulary {field.allowed_values}")
            evidence_table[name] = {"value": value, "raw_value": raw, "evidence": quote,
                                    "status": status, "reason": reason, "canonical_field": targets[name]}
            target = targets[name]
            if target is not None:
                if target not in canonical:
                    raise ContractError(f"Mapping outside POI: {target}")
                if value is not None:
                    if canonical[target] is not None and canonical[target] != value:
                        raise ContractError(f"line_id={line_id}: conflicting source values for {target}")
                    canonical[target] = value
        issues = item.get("issues")
        if not isinstance(issues, list):
            raise ContractError(f"line_id={line_id}: issues must be a list")
        for issue in issues:
            if not isinstance(issue, dict) or issue.get("kind") not in {"missing_field", "mapping_conflict"}:
                raise ContractError(f"line_id={line_id}: invalid upstream issue")
            if not isinstance(issue.get("message"), str) or not issue["message"].strip():
                raise ContractError(f"line_id={line_id}: upstream issue requires a message")
            if not isinstance(issue.get("evidence"), str) or not issue["evidence"] or issue["evidence"] not in record.original_content:
                raise ContractError(f"line_id={line_id}: upstream issue requires an exact quote")
        results.append(ExtractedRecord(
            dataset_id=record.dataset_id, line_id=line_id, template_id=semantics.template_id,
            timestamp=record.timestamp, original_content=record.original_content,
            source_parameters=source, canonical_parameters=canonical, field_evidence=evidence_table,
            status="uncertain" if warnings or issues else "ok",
            metadata={"source_path": record.source_path, "librelog_event_id": record.event_id,
                      "warnings": warnings, "upstream_issues": issues,
                      "unmapped_source_fields": [n for n, v in source.items() if v is not None and targets[n] is None]}))
    if seen != set(expected):
        raise ContractError(f"Missing response line IDs: {sorted(set(expected) - seen)}")
    return sorted(results, key=lambda r: r.line_id)
