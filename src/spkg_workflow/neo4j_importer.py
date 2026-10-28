"""Standalone portable importer; only --apply requires the Neo4j Python driver.

This file is copied verbatim into each import package. No SPKG imports allowed.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import re


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise ValueError(f"Unsafe graph identifier: {value!r}")
    return value


def property_value(value):
    return (isinstance(value, (str, bool)) or isinstance(value, int) and -(2 ** 63) <= value < 2 ** 63
            or isinstance(value, float) and math.isfinite(value))


def validate_package(root):
    root = Path(root).resolve()
    manifest = read_json(root / "manifest.json")
    if manifest.get("format") != "spkg-neo4j-import-v1":
        raise ValueError("Unsupported import package version")
    required = {"nodes.jsonl", "relationships.jsonl", "validation.json", "schema.json",
                "import_neo4j.py", "constraints.cypher", "import.cypher"}
    if not required.issubset(manifest["files"]):
        raise ValueError("Incomplete package file inventory")
    for relative, expected in manifest["files"].items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file() or sha256(path) != expected:
            raise ValueError(f"Missing, escaped or modified package file: {relative}")
    records = []
    for filename in ("nodes.jsonl", "relationships.jsonl"):
        with (root / filename).open(encoding="utf-8") as stream:
            records.append([json.loads(line) for line in stream if line.strip()])
    nodes, edges = records
    ids = set()
    for node in nodes:
        identifier(node["label"])
        if not isinstance(node["id"], str) or not node["id"] or node["id"] in ids:
            raise ValueError("Empty or duplicate node ID")
        ids.add(node["id"])
        check_properties(node["properties"])
    edge_ids = set()
    for edge in edges:
        identifier(edge["type"])
        if not isinstance(edge["id"], str) or not edge["id"] or edge["id"] in edge_ids:
            raise ValueError("Empty or duplicate relationship ID")
        edge_ids.add(edge["id"])
        if edge["start_id"] not in ids or edge["end_id"] not in ids:
            raise ValueError("Dangling relationship endpoint")
        check_properties(edge["properties"])
    if manifest["counts"]["nodes"] != len(nodes) or manifest["counts"]["relationships"] != len(edges):
        raise ValueError("Manifest count mismatch")
    validation = read_json(root / "validation.json")
    if not validation.get("structurally_valid") or validation.get("blocking_errors"):
        raise ValueError("Graph package validation failed")
    return manifest, nodes, edges


def check_properties(properties):
    if not isinstance(properties, dict) or "spkg_id" in properties:
        raise ValueError("Invalid/reserved properties")
    for key, value in properties.items():
        identifier(key)
        if not property_value(value):
            raise ValueError(f"Unsupported property value for {key}")


def node_query(label):
    label = identifier(label)
    return (f"UNWIND $rows AS row MERGE (n:SPKGEntity {{spkg_id: row.id}}) "
            f"SET n:`{label}` SET n += row.properties RETURN count(n) AS processed")


def edge_query(kind):
    kind = identifier(kind)
    return ("UNWIND $rows AS row MATCH (a:SPKGEntity {spkg_id: row.start_id}) "
            "MATCH (b:SPKGEntity {spkg_id: row.end_id}) "
            f"MERGE (a)-[r:`{kind}` {{spkg_id: row.id}}]->(b) "
            "SET r += row.properties RETURN count(r) AS processed")


def constraints(types):
    # Relationship uniqueness constraints require Neo4j >= 5.7; target is 5.26 LTS.
    return ["CREATE CONSTRAINT spkg_entity_id IF NOT EXISTS FOR (n:SPKGEntity) REQUIRE n.spkg_id IS UNIQUE"] + [
        f"CREATE CONSTRAINT spkg_rel_{identifier(t)} IF NOT EXISTS FOR ()-[r:`{t}`]-() REQUIRE r.spkg_id IS UNIQUE"
        for t in sorted(types)]


def apply_package(driver, database, nodes, edges, batch_size=500):
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    for query in constraints({edge["type"] for edge in edges}):
        driver.execute_query(query, database_=database)
    counts = Counter()
    for category, records, discriminator, factory in (
        ("nodes", nodes, "label", node_query), ("relationships", edges, "type", edge_query)
    ):
        groups = defaultdict(list)
        for record in records:
            groups[record[discriminator]].append(record)
        for kind in sorted(groups):
            for offset in range(0, len(groups[kind]), batch_size):
                batch = groups[kind][offset:offset + batch_size]
                result, _, _ = driver.execute_query(factory(kind), parameters_={"rows": batch}, database_=database)
                if len(result) != 1 or result[0]["processed"] != len(batch):
                    raise RuntimeError("Import count mismatch; earlier batches may have committed. Retry the same package.")
                counts[category] += len(batch)
    # Verify actual presence after all commits; do not equate driver success with coverage.
    for category, records in (("nodes", nodes), ("relationships", edges)):
        for offset in range(0, len(records), batch_size):
            batch = records[offset:offset + batch_size]
            if category == "nodes":
                query = "UNWIND $rows AS row MATCH (n:SPKGEntity {spkg_id: row.id}) RETURN count(n) AS processed"
            else:
                query = ("UNWIND $rows AS row MATCH (a:SPKGEntity {spkg_id: row.start_id})"
                         "-[r]->(b:SPKGEntity {spkg_id: row.end_id}) WHERE r.spkg_id = row.id RETURN count(r) AS processed")
            result, _, _ = driver.execute_query(query, parameters_={"rows": batch}, database_=database)
            if result[0]["processed"] != len(batch):
                raise RuntimeError("Post-import verification failed")
    return dict(counts)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate offline by default; --apply explicitly writes to Neo4j")
    parser.add_argument("--package", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--allow-rejected", action="store_true", help="Explicitly import the accepted subset of a partial package")
    parser.add_argument("--batch-size", type=int, default=500)
    args = parser.parse_args(argv)
    manifest, nodes, edges = validate_package(args.package)
    report = {"mode": "offline_validation", "package_id": manifest["package_id"],
              "counts": manifest["counts"], "database_written": False}
    if args.apply:
        if manifest["counts"].get("rejected_records", 0) and not args.allow_rejected:
            raise ValueError("Package contains rejected records. Review rejected.jsonl; use --allow-rejected explicitly.")
        uri, username, password = (os.environ.get(k) for k in ("NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD"))
        if not all((uri, username, password)):
            raise ValueError("Set NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD; credentials are never embedded in the package")
        from neo4j import GraphDatabase
        database = os.environ.get("NEO4J_DATABASE", "neo4j")
        with GraphDatabase.driver(uri, auth=(username, password)) as driver:
            driver.verify_connectivity()
            counts = apply_package(driver, database, nodes, edges, args.batch_size)
        report.update(mode="neo4j_import", database_written=True, verified_counts=counts)
        (args.package / "import_receipt.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Database exceptions may echo data or connection details. Do not print credentials.
        message = str(exc)
        for key in ("NEO4J_PASSWORD", "NEO4J_URI"):
            if os.environ.get(key):
                message = message.replace(os.environ[key], "[REDACTED]")
        raise SystemExit(f"Import failed ({type(exc).__name__}): {message}")
