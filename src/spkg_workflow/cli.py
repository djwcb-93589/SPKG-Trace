from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from spkg_workflow.config import PROJECT_ROOT, load_pipeline_config
from spkg_workflow.dataset_config import load_dataset_spec
from spkg_workflow.workflow import run_workflow


def _dataset_path(value: str) -> Path:
    candidate = Path(value)
    if candidate.is_file() or candidate.is_absolute() or candidate.suffix:
        return candidate
    return PROJECT_ROOT / "configs" / "datasets" / f"{value}.yaml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spkg-workflow",
        description="Raw log to graph-ready SPKG knowledge package (graph build disabled).",
    )
    parser.add_argument("--pipeline-config", default=str(PROJECT_ROOT / "configs" / "pipeline.yaml"))
    parser.add_argument("--env-file", default=str(PROJECT_ROOT / ".env.local"))
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run all stages in their fixed order")
    run_parser.add_argument(
        "dataset",
        help="Dataset ID from configs/datasets or a dataset YAML path",
    )
    run_parser.add_argument("--resume", action="store_true", help="Reuse matching stage checkpoints and parameter cache")

    export_parser = subparsers.add_parser("export-neo4j", help="Build offline Neo4j import files from an existing sealed knowledge package; no LLM or database calls")
    export_parser.add_argument("dataset", help="Dataset ID or YAML path")
    export_parser.add_argument("--policy", help="Optional graph identity/condition policy YAML")

    subparsers.add_parser("list-datasets", help="List bundled dataset IDs")
    subparsers.add_parser("show-config", help="Show non-secret provider configuration")
    check_parser = subparsers.add_parser("check-llm", help="Check configured model IDs; optionally send synthetic JSON, never log data")
    check_parser.add_argument("--generate", action="store_true", help="Also make one small JSON generation request per model")
    check_parser.add_argument("--max-tokens", type=int, default=1024, help="Synthetic check output budget, including reasoning")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list-datasets":
        for path in sorted((PROJECT_ROOT / "configs" / "datasets").glob("*.yaml")):
            print(path.stem)
        return 0

    try:
        settings = load_pipeline_config(
            args.pipeline_config,
            args.env_file,
            require_api_key=args.command in {"run", "check-llm"},
        )
        if args.command == "show-config":
            print(json.dumps(settings.public_summary(), ensure_ascii=False, indent=2))
            return 0
        if args.command == "check-llm":
            from spkg_workflow.providers import OpenAICompatibleClient
            report = OpenAICompatibleClient(settings.provider).check_connection(generate=args.generate, max_tokens=args.max_tokens)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0
        dataset = load_dataset_spec(_dataset_path(args.dataset))
        if args.command == "export-neo4j":
            from spkg_workflow.stages.neo4j_export import export_package
            root = settings.resolve_path((settings.raw.get("project") or {}).get("results_dir", "results"))
            policy = args.policy or (settings.raw.get("knowledge_package") or {}).get("graph_export_policy", "configs/graph_export.yaml")
            result = export_package(root / dataset.dataset_id / "06_knowledge_package", settings.resolve_path(policy))
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if not result["counts"]["rejected_records"] else 3
        result = run_workflow(dataset, settings=settings, progress=lambda message: print(message, flush=True), resume=args.resume)
        print(str(result.knowledge_package.manifest_path))
        return 0 if result.knowledge_package.manifest.quality.get("processing_status") == "complete" else 3
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
