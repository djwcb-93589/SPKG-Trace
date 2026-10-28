from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from spkg_workflow.contracts import JsonValue, ParsedLogRecord


@dataclass(frozen=True, slots=True)
class ExtractorContext:
    family: str
    log_source: str
    default_host: str = ""
    default_program: str = ""


@dataclass(slots=True)
class FamilyExtraction:
    source_values: dict[str, JsonValue] = field(default_factory=dict)
    canonical_values: dict[str, JsonValue] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class FamilyExtractor(Protocol):
    family: str

    def extract(
        self, record: ParsedLogRecord, context: ExtractorContext
    ) -> FamilyExtraction: ...
