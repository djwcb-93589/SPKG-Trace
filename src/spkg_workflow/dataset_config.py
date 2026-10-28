from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
import re

from spkg_workflow.config import PROJECT_ROOT


class DatasetConfigurationError(ValueError):
    """Raised when a dataset configuration is incomplete or invalid."""


@dataclass(frozen=True, slots=True)
class DatasetSpec:
    dataset_id: str
    family: str
    log_source: str
    raw_log: Path
    baseline_parsed_csv: Path | None
    poi_schema: Path
    relation_schema: Path
    mapping_overrides: Path | None
    default_host: str
    default_program: str
    config_path: Path


def _resolve_path(value: Any, *, required: bool) -> Path | None:
    if value is None or str(value).strip() == "":
        if required:
            raise DatasetConfigurationError("A required dataset path is empty")
        return None
    path = Path(str(value))
    return path.resolve() if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def load_dataset_spec(path: str | Path) -> DatasetSpec:
    source = Path(path)
    if not source.is_absolute():
        source = (PROJECT_ROOT / source).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"Dataset config does not exist: {source}")
    payload = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise DatasetConfigurationError("Dataset config root must be an object")
    if int(payload.get("version", 0)) != 1:
        raise DatasetConfigurationError("Dataset config version must be 1")
    required_text = ("dataset_id", "family", "log_source")
    missing = [name for name in required_text if not str(payload.get(name, "")).strip()]
    if missing:
        raise DatasetConfigurationError(
            "Dataset config is missing: " + ", ".join(missing)
        )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", str(payload["dataset_id"])):
        raise DatasetConfigurationError("dataset_id must be a single safe directory name")
    defaults = payload.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise DatasetConfigurationError("defaults must be an object")
    return DatasetSpec(
        dataset_id=str(payload["dataset_id"]).strip(),
        family=str(payload["family"]).strip(),
        log_source=str(payload["log_source"]).strip(),
        raw_log=_resolve_path(payload.get("raw_log"), required=True),  # type: ignore[arg-type]
        baseline_parsed_csv=_resolve_path(
            payload.get("baseline_parsed_csv"), required=False
        ),
        poi_schema=_resolve_path(payload.get("poi_schema"), required=True),  # type: ignore[arg-type]
        relation_schema=_resolve_path(
            payload.get("relation_schema"), required=True
        ),  # type: ignore[arg-type]
        mapping_overrides=_resolve_path(
            payload.get("mapping_overrides"), required=False
        ),
        default_host=str(defaults.get("host", "")),
        default_program=str(defaults.get("program", "")),
        config_path=source,
    )
