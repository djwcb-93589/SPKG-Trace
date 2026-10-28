from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import shutil
from typing import Mapping

from spkg_workflow.config import WorkflowSettings
from spkg_workflow.contracts import (
    KnowledgePackageManifest,
    SchemaAsset,
    write_json,
)


class KnowledgePackageError(RuntimeError):
    """Raised when a graph-ready package cannot be assembled safely."""


@dataclass(frozen=True, slots=True)
class KnowledgePackageResult:
    package_dir: Path
    manifest_path: Path
    manifest: KnowledgePackageManifest


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_artifact_name(name: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", name.strip().lower()).strip("_")
    if not normalized:
        raise KnowledgePackageError(f"Invalid artifact name: {name!r}")
    return normalized


def build_knowledge_package(
    *,
    settings: WorkflowSettings,
    package_dir: str | Path,
    package_id: str,
    dataset_id: str,
    source_files: tuple[str, ...],
    artifact_paths: Mapping[str, str | Path],
    record_counts: Mapping[str, int],
    poi_schema_path: str | Path,
    relation_schema_path: str | Path,
    poi_schema_id: str,
    relation_schema_id: str,
    quality: Mapping | None = None,
    provenance: Mapping | None = None,
) -> KnowledgePackageResult:
    package_config = settings.raw.get("knowledge_package") or {}
    if bool(package_config.get("build_graph", False)):
        raise KnowledgePackageError(
            "Graph construction is intentionally disabled for this migration"
        )
    if bool(package_config.get("write_neo4j", False)):
        raise KnowledgePackageError(
            "Neo4j writes are intentionally disabled for this migration"
        )

    root = Path(package_dir).resolve()
    artifact_dir = root / "artifacts"
    schema_dir = root / "schema"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    schema_dir.mkdir(parents=True, exist_ok=True)

    manifest_artifacts: dict[str, str] = {}
    artifact_hashes: dict[str, str] = {}
    used_names: set[str] = set()
    for logical_name, source_value in artifact_paths.items():
        source = Path(source_value).resolve()
        if not source.is_file():
            raise FileNotFoundError(f"Knowledge-package artifact is missing: {source}")
        safe_name = _safe_artifact_name(logical_name)
        suffix = "".join(source.suffixes) or ".dat"
        target_name = f"{safe_name}{suffix}"
        if target_name in used_names:
            raise KnowledgePackageError(f"Artifact target name collision: {target_name}")
        used_names.add(target_name)
        target = artifact_dir / target_name
        shutil.copy2(source, target)
        relative = target.relative_to(root).as_posix()
        manifest_artifacts[logical_name] = relative
        artifact_hashes[logical_name] = sha256_file(target)

    schema_assets: list[SchemaAsset] = []
    for kind, schema_id, source_value, target_name in (
        ("poi", poi_schema_id, poi_schema_path, "poi.csv"),
        ("relation", relation_schema_id, relation_schema_path, "relations.csv"),
    ):
        source = Path(source_value).resolve()
        if not source.is_file():
            raise FileNotFoundError(f"Schema asset is missing: {source}")
        target = schema_dir / target_name
        shutil.copy2(source, target)
        schema_assets.append(
            SchemaAsset(
                kind=kind,  # type: ignore[arg-type]
                schema_id=schema_id,
                relative_path=target.relative_to(root).as_posix(),
                sha256=sha256_file(target),
            )
        )

    manifest = KnowledgePackageManifest.create(
        package_id=package_id,
        dataset_id=dataset_id,
        source_files=source_files,
        artifacts=manifest_artifacts,
        artifact_sha256=artifact_hashes,
        record_counts=record_counts,
        schema_assets=schema_assets,
        quality=quality,
        provenance=provenance,
    )
    manifest_path = root / "manifest.json"
    write_json(manifest_path, manifest)
    if package_config.get("prepare_neo4j_import", False):
        from spkg_workflow.stages.neo4j_export import export_package
        import json
        export_package(root, settings.resolve_path(package_config.get("graph_export_policy", "configs/graph_export.yaml")))
        manifest = KnowledgePackageManifest.from_dict(json.loads(manifest_path.read_text(encoding="utf-8")))
    return KnowledgePackageResult(
        package_dir=root,
        manifest_path=manifest_path,
        manifest=manifest,
    )
