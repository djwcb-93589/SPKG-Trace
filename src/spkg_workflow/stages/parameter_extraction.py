from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, Mapping

from spkg_workflow.config import WorkflowSettings
from spkg_workflow.contracts import ExtractedRecord, ParsedLogRecord, TemplateFieldMapping, TemplateFieldSemantics, TemplateRecord
from spkg_workflow.stages.llm_parameters import LLMParameterExtractor, ParameterExtractionBatch
from spkg_workflow.stages.poi_mapping import PoiSchema


def extract_parameters(
    parsed_records: Iterable[ParsedLogRecord], templates: Iterable[TemplateRecord],
    semantics_records: Iterable[TemplateFieldSemantics], mappings: Iterable[TemplateFieldMapping],
    *, settings: WorkflowSettings, poi_schema: PoiSchema, output_dir: str | Path,
    log_source: str, family: str = "", overrides: Mapping | None = None,
    client=None, progress=None,
) -> ParameterExtractionBatch:
    extractor = LLMParameterExtractor(settings=settings, poi_schema=poi_schema,
                                      output_dir=Path(output_dir), client=client)
    return extractor.extract(parsed_records, templates, semantics_records, mappings,
                             log_source=log_source, family=family, overrides=overrides, progress=progress)


def write_parameter_csv(path: str | Path, records: Iterable[ExtractedRecord],
                        *, canonical_fields: Iterable[str]) -> int:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fields = tuple(canonical_fields)
    columns = ("LineId", "log", "time", "log_source", "record_status", *fields)
    count = 0
    with target.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            row = {"LineId": record.line_id, "log": record.original_content,
                   "time": record.timestamp, "log_source": record.metadata.get("log_source"),
                   "record_status": record.status}
            # Legacy graph readers ignore status: quarantine non-ok values in CSV.
            row.update(record.canonical_parameters if record.status == "ok" else {f: None for f in fields})
            writer.writerow({k: "" if v is None else v for k, v in row.items()})
            count += 1
    return count
