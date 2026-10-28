from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, ClassVar, Iterable, Literal, Mapping, TypeVar


CONTRACT_VERSION = "1.1"
JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
T = TypeVar("T", bound="ContractRecord")


class ContractError(ValueError):
    """Raised when an artifact violates a workflow data contract."""


@dataclass(frozen=True, slots=True)
class ContractRecord:
    """Base class for versioned, JSON-serializable workflow records."""

    record_type: ClassVar[str] = "contract_record"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload = _json_compatible(payload)
        return {
            "contract_version": CONTRACT_VERSION,
            "record_type": self.record_type,
            **payload,
        }

    @classmethod
    def from_dict(cls: type[T], payload: Mapping[str, Any]) -> T:
        version = str(payload.get("contract_version", CONTRACT_VERSION))
        if version not in {"1.0", CONTRACT_VERSION}:
            raise ContractError(
                f"Unsupported contract version {version!r}; expected {CONTRACT_VERSION!r}"
            )
        record_type = payload.get("record_type")
        if record_type not in (None, cls.record_type):
            raise ContractError(
                f"Expected record_type={cls.record_type!r}, got {record_type!r}"
            )
        allowed = {item.name for item in fields(cls)}
        values = {key: value for key, value in payload.items() if key in allowed}
        try:
            return cls(**values)
        except TypeError as exc:
            raise ContractError(f"Invalid {cls.record_type} record: {exc}") from exc


@dataclass(frozen=True, slots=True)
class RawLogRecord(ContractRecord):
    record_type: ClassVar[str] = "raw_log"

    dataset_id: str
    line_id: int
    original_content: str
    source_path: str
    timestamp: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedLogRecord(ContractRecord):
    record_type: ClassVar[str] = "parsed_log"

    dataset_id: str
    line_id: int
    timestamp: str
    content: str
    original_content: str
    event_id: str
    regex_template: str
    regex_pattern: str
    source_path: str


@dataclass(frozen=True, slots=True)
class TemplateRecord(ContractRecord):
    record_type: ClassVar[str] = "template"

    dataset_id: str
    template_id: str
    event_id: str
    regex_template: str
    regex_pattern: str
    occurrence_count: int
    event_ids: tuple[str, ...] = ()
    sample_line_ids: tuple[int, ...] = ()
    samples: tuple[str, ...] = ()


ExtractionKind = Literal[
    "capture", "capture_fragment", "key_value", "constant", "unbound", "llm"
]


@dataclass(frozen=True, slots=True)
class FieldSemantic(ContractRecord):
    record_type: ClassVar[str] = "field_semantic"

    source_field: str
    definition: str
    examples: tuple[str, ...] = ()
    capture_index: int | None = None
    extraction_kind: ExtractionKind = "unbound"
    source_key: str | None = None
    nullable: bool = True
    value_kind: Literal["literal", "normalized", "derived"] = "literal"
    allowed_values: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "FieldSemantic":
        values = dict(payload)
        values["examples"] = tuple(payload.get("examples", []))
        values["allowed_values"] = tuple(payload.get("allowed_values", []))
        return ContractRecord.from_dict.__func__(cls, values)


@dataclass(frozen=True, slots=True)
class TemplateFieldSemantics(ContractRecord):
    record_type: ClassVar[str] = "template_field_semantics"

    dataset_id: str
    template_id: str
    regex_pattern: str
    fields: tuple[FieldSemantic, ...]
    warnings: tuple[str, ...] = ()
    revision: int = 1
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = ContractRecord.to_dict(self)
        payload["fields"] = [item.to_dict() for item in self.fields]
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "TemplateFieldSemantics":
        values = dict(payload)
        values["fields"] = tuple(
            FieldSemantic.from_dict(item) for item in payload.get("fields", [])
        )
        values["warnings"] = tuple(payload.get("warnings", []))
        return ContractRecord.from_dict.__func__(cls, values)


MappingStatus = Literal["mapped", "unmapped", "override"]


@dataclass(frozen=True, slots=True)
class FieldMapping(ContractRecord):
    record_type: ClassVar[str] = "field_mapping"

    source_field: str
    source_definition: str
    canonical_field: str | None
    canonical_definition: str | None
    status: MappingStatus
    rationale: str = ""


@dataclass(frozen=True, slots=True)
class TemplateFieldMapping(ContractRecord):
    record_type: ClassVar[str] = "template_field_mapping"

    dataset_id: str
    template_id: str
    poi_schema_id: str
    mappings: tuple[FieldMapping, ...]
    warnings: tuple[str, ...] = ()
    revision: int = 1
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = ContractRecord.to_dict(self)
        payload["mappings"] = [item.to_dict() for item in self.mappings]
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "TemplateFieldMapping":
        values = dict(payload)
        values["mappings"] = tuple(
            FieldMapping.from_dict(item) for item in payload.get("mappings", [])
        )
        values["warnings"] = tuple(payload.get("warnings", []))
        return ContractRecord.from_dict.__func__(cls, values)


@dataclass(frozen=True, slots=True)
class ExtractedRecord(ContractRecord):
    record_type: ClassVar[str] = "extracted_record"

    dataset_id: str
    line_id: int
    template_id: str
    timestamp: str
    original_content: str
    source_parameters: dict[str, JsonValue]
    canonical_parameters: dict[str, JsonValue]
    metadata: dict[str, JsonValue] = field(default_factory=dict)
    field_evidence: dict[str, JsonValue] = field(default_factory=dict)
    status: Literal["ok", "uncertain", "error"] = "ok"


@dataclass(frozen=True, slots=True)
class ExtractionError(ContractRecord):
    record_type: ClassVar[str] = "extraction_error"

    dataset_id: str
    line_id: int | None
    template_id: str | None
    stage: str
    code: str
    message: str
    original_content: str | None = None


@dataclass(frozen=True, slots=True)
class SchemaAsset(ContractRecord):
    record_type: ClassVar[str] = "schema_asset"

    kind: Literal["poi", "relation"]
    schema_id: str
    relative_path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class KnowledgePackageManifest(ContractRecord):
    record_type: ClassVar[str] = "knowledge_package_manifest"

    package_id: str
    dataset_id: str
    created_at: str
    source_files: tuple[str, ...]
    artifacts: dict[str, str]
    artifact_sha256: dict[str, str]
    record_counts: dict[str, int]
    schema_assets: tuple[SchemaAsset, ...]
    graph_construction_enabled: bool = False
    neo4j_write_enabled: bool = False
    quality: dict[str, JsonValue] = field(default_factory=dict)
    provenance: dict[str, JsonValue] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        package_id: str,
        dataset_id: str,
        source_files: Iterable[str],
        artifacts: Mapping[str, str],
        artifact_sha256: Mapping[str, str],
        record_counts: Mapping[str, int],
        schema_assets: Iterable[SchemaAsset],
        quality: Mapping[str, JsonValue] | None = None,
        provenance: Mapping[str, JsonValue] | None = None,
    ) -> "KnowledgePackageManifest":
        return cls(
            package_id=package_id,
            dataset_id=dataset_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            source_files=tuple(source_files),
            artifacts=dict(artifacts),
            artifact_sha256=dict(artifact_sha256),
            record_counts=dict(record_counts),
            schema_assets=tuple(schema_assets),
            graph_construction_enabled=False,
            neo4j_write_enabled=False,
            quality=dict(quality or {}),
            provenance=dict(provenance or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = ContractRecord.to_dict(self)
        payload["schema_assets"] = [item.to_dict() for item in self.schema_assets]
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "KnowledgePackageManifest":
        values = dict(payload)
        values["source_files"] = tuple(payload.get("source_files", []))
        values["schema_assets"] = tuple(
            SchemaAsset.from_dict(item) for item in payload.get("schema_assets", [])
        )
        return ContractRecord.from_dict.__func__(cls, values)


def _json_compatible(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [_json_compatible(item) for item in value]
    if isinstance(value, list):
        return [_json_compatible(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    return value


def write_json(path: str | Path, record: ContractRecord) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(record.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: str | Path, records: Iterable[ContractRecord]) -> int:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
            count += 1
    return count


def read_jsonl(path: str | Path, record_class: type[T]) -> list[T]:
    source = Path(path)
    records: list[T] = []
    with source.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ContractError(
                    f"Invalid JSON in {source} at line {line_number}: {exc.msg}"
                ) from exc
            if not isinstance(payload, dict):
                raise ContractError(
                    f"Expected a JSON object in {source} at line {line_number}"
                )
            records.append(record_class.from_dict(payload))
    return records
