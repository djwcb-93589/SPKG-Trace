"""Deterministic, offline graph materialization from a sealed knowledge package."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile

import yaml

from spkg_workflow import neo4j_importer as importer


RELATION_COLUMNS = ["subject_type", "subject_id_source", "predicate", "object_type", "object_id_source", "edge_properties", "condition"]
SCOPE_COLUMNS = {"subject_scope", "object_scope"}
SCOPES = {"event", "dataset", "host", "global"}


def validate_relation_header(columns):
    if (not columns or columns[:7] != RELATION_COLUMNS or
            len(set(columns)) != len(columns) or not set(columns[7:]).issubset(SCOPE_COLUMNS)):
        raise ValueError("关系 CSV 需要标准七列表头；仅允许追加 subject_scope、object_scope 列")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def present(value):
    return value is not None and value != ""


def literal(value):
    value = value.strip()
    if re.fullmatch(r"[A-Za-z0-9_.:/-]+", value):
        return value
    if re.fullmatch(r"'[^']*'|\"[^\"]*\"", value):
        return value[1:-1]
    raise ValueError(f"Unsupported condition literal: {value}")


def compile_condition(text, fields, aliases):
    """Small allowlisted grammar. Never eval() or execute schema-supplied text."""
    clauses = []
    for fragment in re.split(r"\s+AND\s+", text.strip(), flags=re.I):
        match = re.fullmatch(r"([a-zA-Z_]\w*)\s+(.+)", fragment)
        if not match or match[1] not in fields:
            raise ValueError(f"Unknown field/invalid condition: {fragment}")
        field, expression = match.groups()
        if re.fullmatch(r"(?:is\s+)?not\s+null", expression, re.I):
            operator, values = "present", []
        elif re.fullmatch(r"is\s+null", expression, re.I):
            operator, values = "absent", []
        elif matched := re.fullmatch(r"indicates\s+([A-Za-z0-9_]+)", expression, re.I):
            values = aliases.get(field, {}).get(matched[1])
            if not isinstance(values, list) or not values or not all(isinstance(v, str) for v in values):
                raise ValueError(f"条件 {field} indicates {matched[1]} 没有明确取值集合；"
                                 f"请在关系 CSV 中改写为 {field} in (value1,value2)，无需修改 YAML")
            operator = "in"
        elif matched := re.fullmatch(r"in\s*\(([^()]*)\)", expression, re.I):
            operator, values = "in", [literal(v) for v in matched[1].split(",")]
        elif matched := re.fullmatch(r"(!=|==|=)\s*(.+)", expression):
            operator, values = ("not_in" if matched[1] == "!=" else "in"), [literal(matched[2])]
        else:
            raise ValueError(f"Unsupported condition: {fragment}")
        clauses.append({"field": field, "operator": operator, "values": values})
    return clauses


def matches(clauses, values):
    for clause in clauses:
        value, op = values.get(clause["field"]), clause["operator"]
        if op == "present" and not present(value) or op == "absent" and present(value):
            return False
        if op in {"in", "not_in"}:
            if not present(value):
                return False
            found = str(value) in clause["values"]
            if op == "in" and not found or op == "not_in" and found:
                return False
    return True


def compile_schema(poi_path, relation_path, policy):
    if not isinstance(policy, dict) or policy.get("version") != 1:
        raise ValueError("graph_export policy version must be 1")
    policy = deepcopy(policy)
    node_types = policy.setdefault("node_types", {})
    if not isinstance(node_types, dict):
        raise ValueError("Invalid node_types policy")
    with poi_path.open(encoding="utf-8-sig", newline="") as stream:
        poi = [row[0].strip() for row in csv.reader(stream) if row and row[0].strip()]
    if not poi or len(set(poi)) != len(poi):
        raise ValueError("Invalid POI field inventory")
    fields = set(poi) | {"timestamp", "log_source"}
    for field in fields:
        importer.identifier(field)
    rules, explicit_scopes, defaulted_types = [], {}, set()
    with relation_path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        validate_relation_header(reader.fieldnames)
        rows = list(reader)
        # Resolve all per-type declarations first, independent of CSV row order.
        for row in rows:
            if None in row or any(v is None for v in row.values()):
                raise ValueError("Malformed relation schema row")
            for side in ("subject", "object"):
                kind, scope = row[side + "_type"], row.get(side + "_scope", "").strip()
                if scope:
                    if scope not in SCOPES:
                        raise ValueError(f"节点 {kind} 的 scope 必须为 event/dataset/host/global")
                    if kind in explicit_scopes and explicit_scopes[kind] != scope:
                        raise ValueError(f"节点 {kind} 在关系 CSV 中声明了冲突的 scope")
                    explicit_scopes[kind] = scope
        for kind, scope in explicit_scopes.items():
            previous = node_types.get(kind, {})
            if not isinstance(previous, dict):
                raise ValueError(f"Invalid node identity policy: {kind}")
            node_types[kind] = {**previous, "scope": scope}
        for source_row in rows:
            row = {k: source_row[k] for k in RELATION_COLUMNS}
            for key in ("subject_type", "object_type", "predicate"):
                importer.identifier(row[key])
            for key in ("subject_type", "object_type"):
                kind = row[key]
                if kind not in node_types:
                    node_types[kind] = {"scope": "event"}
                    defaulted_types.add(kind)
                node = node_types[kind]
                if kind in {"LogEvent", "SPKGEntity"} or not isinstance(node, dict) or node.get("scope") not in SCOPES:
                    raise ValueError(f"Missing/invalid node identity policy: {kind}")
            properties = [p.strip() for p in row["edge_properties"].split(",") if p.strip()]
            refs = {row["subject_id_source"], row["object_id_source"], *properties}
            if not refs.issubset(fields):
                raise ValueError(f"Schema references unknown POI fields: {sorted(refs - fields)}")
            if row["predicate"] == "MENTIONS":
                raise ValueError("MENTIONS is reserved for event provenance")
            clauses = compile_condition(row["condition"], fields, policy.get("indicates", {}))
            rule = {**row, "properties": properties, "clauses": clauses}
            rule["id"] = digest(rule)
            if any(existing["id"] == rule["id"] for existing in rules):
                raise ValueError("Duplicate relation rule")
            rules.append(rule)
    if not rules:
        raise ValueError("Relation schema must contain rules")
    schema = {"version": 1, "poi_fields": poi, "identity_policy": policy, "rules": rules}
    if defaulted_types:
        schema["warnings"] = [f"节点 {kind} 未声明 scope，默认 event：不同日志中的同值不会自动合并。"
                              for kind in sorted(defaulted_types)]
    return schema


def materialize(records, schema, *, dataset, source_hash, snapshot):
    nodes, edges, rejected = {}, {}, []
    rule_counts = {r["id"]: Counter() for r in schema["rules"]}
    seen_lines, vocabulary = set(), {}
    specs = sorted({(r[t], r[f]) for r in schema["rules"] for t, f in (
        ("subject_type", "subject_id_source"), ("object_type", "object_id_source"))})
    def add_edge(kind, start, end, discriminator, props):
        identity = digest([snapshot, kind, start, end, discriminator])
        edge = {"id": identity, "type": kind, "start_id": start, "end_id": end, "properties": props}
        if identity in edges and edges[identity] != edge:
            raise ValueError("Conflicting relationship identity")
        edges[identity] = edge
    for record in records:
        line = record.get("line_id")
        if not isinstance(line, int) or isinstance(line, bool) or line <= 0 or line in seen_lines:
            raise ValueError("Invalid/duplicate source line identity")
        seen_lines.add(line)
        if record.get("dataset_id") != dataset:
            raise ValueError("Parameter dataset does not match package")
        if record.get("status") != "ok":
            rejected.append({"line_id": line, "reason": "non_ok_record", "status": record.get("status")})
            continue
        params = record.get("canonical_parameters", {})
        if set(params) != set(schema["poi_fields"]):
            raise ValueError("Parameter fields do not match packaged POI")
        if any(v is not None and not importer.property_value(v) for v in params.values()):
            rejected.append({"line_id": line, "reason": "unsupported_parameter_type"})
            continue
        if not isinstance(record.get("original_content"), str) or not record["original_content"]:
            rejected.append({"line_id": line, "reason": "missing_original_evidence"})
            continue
        values = {**params, "timestamp": record.get("timestamp") or "",
                  "log_source": record.get("metadata", {}).get("log_source", "")}
        for field in ("event_type", "event_action"):
            vocabulary.setdefault(field, Counter())[str(values.get(field))] += 1
        event = digest([snapshot, "event", line])
        event_props = {"dataset_id": dataset, "snapshot_id": snapshot, "line_id": line,
                       "source_sha256": source_hash, "template_id": record.get("template_id", ""),
                       "timestamp_raw": values["timestamp"], "time_precision": "raw_unresolved",
                       "original_content": record["original_content"],
                       "field_evidence_json": json.dumps(record.get("field_evidence", {}), ensure_ascii=False),
                       **{"poi_" + k: v for k, v in params.items() if v is not None}}
        importer.check_properties(event_props)
        nodes[event] = {"id": event, "label": "LogEvent", "properties": event_props}
        references = {}
        for kind, field in specs:
            value = values.get(field)
            if not present(value):
                continue
            policy = schema["identity_policy"]["node_types"][kind]
            scope = policy["scope"]
            scope_value = {"event": event, "dataset": dataset, "global": "snapshot"}.get(scope)
            if scope == "host":
                scope_value = "host:" + str(values["host"]) if present(values.get("host")) else "dataset:" + dataset
            qualifier = field if policy.get("distinguish_field") else ""
            identity = digest([snapshot, kind, scope_value, qualifier, value])
            props = {"value": value, "snapshot_id": snapshot, "identity_scope": scope,
                     "scope_value": scope_value, "identity_kind": "observation" if scope == "event" else "entity"}
            if qualifier:
                props["value_role"] = qualifier
            nodes[identity] = {"id": identity, "label": kind, "properties": props}
            references[(kind, field)] = identity
            add_edge("MENTIONS", event, identity, field, {"field": field, "event_id": event, "line_id": line})
        for rule in schema["rules"]:
            counter = rule_counts[rule["id"]]
            if not matches(rule["clauses"], values):
                counter["condition_false"] += 1
                continue
            start = references.get((rule["subject_type"], rule["subject_id_source"]))
            end = references.get((rule["object_type"], rule["object_id_source"]))
            if start is None or end is None:
                counter["missing_endpoint"] += 1
                continue
            props = {"event_id": event, "line_id": line, "rule_id": rule["id"], "timestamp_raw": values["timestamp"],
                     **{"poi_" + f: values[f] for f in rule["properties"] if values.get(f) is not None}}
            add_edge(rule["predicate"], start, end, [event, rule["id"]], props)
            counter["emitted"] += 1
    validation = {"structurally_valid": True, "blocking_errors": [], "semantic_accuracy_verified": False,
        "schema_warnings": schema.get("warnings", []),
        "rejected_records": len(rejected), "input_records": len(seen_lines),
        "node_labels": dict(Counter(n["label"] for n in nodes.values())),
        "relationship_types": dict(Counter(e["type"] for e in edges.values())),
        "rule_counts": {r["id"]: {"predicate": r["predicate"], **dict(rule_counts[r["id"]])} for r in schema["rules"]},
        "observed_vocabulary": {f: dict(v) for f, v in vocabulary.items()},
        "limitations": ["No cross-record entity inference; Process/Session defaults are event-scoped observations.",
                        "Node identities are isolated by content-addressed graph snapshot; changed inputs create a new snapshot.",
                        "Timestamps are preserved verbatim; year/timezone are not invented.",
                        "False relation conditions are counted, not treated as proof of absent real-world relations.",
                        "No live Neo4j write occurred during export; structural validity is not semantic accuracy."]}
    return sorted(nodes.values(), key=lambda r: r["id"]), sorted(edges.values(), key=lambda r: r["id"]), rejected, validation


README = """# Standalone Neo4j import package

Target: Neo4j 5.26 LTS; Python 3.10+. This package needs neither SPKG nor an LLM.
Keep all generated files together.

1. Run python import_neo4j.py for offline integrity and structural validation.
2. For database import only, install requirements-import.txt.
3. Privately configure NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD, and optionally
   NEO4J_DATABASE (default: neo4j). Never store credentials in this package.
4. Test against an empty disposable database, then explicitly run
   python import_neo4j.py --apply.

JSONL files are authoritative. CSV files are inspection mirrors, not native
neo4j-admin inputs. import.cypher contains parameterized queries whose rows are
supplied by the importer; it is not a standalone LOAD CSV script.

Stable IDs and MERGE support repeated imports of the same package. Transactions
are batched, not atomic across the whole package. Changed inputs or rules create
a new snapshot; previous snapshots are not automatically deleted or merged.

Event nodes preserve original text, canonical fields, and evidence. MENTIONS
edges retain field provenance. Process/Session default to event observations,
not inferred cross-record entities. Timestamps remain unresolved raw values.
Only compiled finite conditions are executed; arbitrary schema code is forbidden.

Rejected records are excluded; importing a partial package requires explicit
review and --allow-rejected. validation.json reports structural checks and
coverage, not semantic accuracy. Artifact generation does not verify live import.
"""


def export_package(package_dir, policy_path):
    root = Path(package_dir).resolve()
    original_manifest = root / "manifest.json"
    manifest = importer.read_json(original_manifest)
    if manifest.get("record_type") != "knowledge_package_manifest":
        raise ValueError("Expected an SPKG knowledge package")
    def asset(relative, expected):
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file() or importer.sha256(path) != expected:
            raise ValueError(f"Knowledge package integrity check failed: {relative}")
        return path
    # Validate original extraction assets only; previous exports may be regenerated.
    for name, relative in manifest["artifacts"].items():
        if not name.startswith("neo4j_"):
            asset(relative, manifest["artifact_sha256"][name])
    schemas = {s["kind"]: asset(s["relative_path"], s["sha256"]) for s in manifest["schema_assets"]}
    params = asset(manifest["artifacts"]["parameters_jsonl"], manifest["artifact_sha256"]["parameters_jsonl"])
    policy = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8"))
    schema = compile_schema(schemas["poi"], schemas["relation"], policy)
    source_hash = manifest.get("provenance", {}).get("raw_log_sha256")
    if not isinstance(source_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", source_hash):
        raise ValueError("Knowledge package must declare raw_log_sha256")
    snapshot = digest(["graph-v1", manifest["dataset_id"], source_hash, importer.sha256(params), schema])
    with params.open(encoding="utf-8") as stream:
        nodes, edges, rejected, validation = materialize(
            (json.loads(line) for line in stream if line.strip()), schema,
            dataset=manifest["dataset_id"], source_hash=source_hash, snapshot=snapshot)
    if len(nodes) == 0:
        raise ValueError("No valid records available for graph export")
    with tempfile.TemporaryDirectory(prefix=".neo4j-stage-", dir=root) as temp:
        staging = Path(temp) / "neo4j"
        staging.mkdir()
        for name, rows in (("nodes", nodes), ("relationships", edges), ("rejected", rejected)):
            with (staging / (name + ".jsonl")).open("w", encoding="utf-8", newline="\n") as stream:
                for row in rows:
                    stream.write(json.dumps(row, ensure_ascii=False) + "\n")
            if name != "rejected":
                columns = ["id", "label", "properties_json"] if name == "nodes" else ["id", "type", "start_id", "end_id", "properties_json"]
                with (staging / (name + ".csv")).open("w", encoding="utf-8-sig", newline="") as stream:
                    writer = csv.DictWriter(stream, fieldnames=columns)
                    writer.writeheader()
                    for row in rows:
                        writer.writerow({**{k: v for k, v in row.items() if k != "properties"},
                                         "properties_json": json.dumps(row["properties"], ensure_ascii=False)})
        save(staging / "schema.json", schema)
        save(staging / "validation.json", validation)
        shutil.copyfile(Path(importer.__file__), staging / "import_neo4j.py")
        (staging / "requirements-import.txt").write_text("neo4j>=5.26,<6\n", encoding="utf-8")
        (staging / "README.md").write_text(README, encoding="utf-8")
        (staging / "constraints.cypher").write_text(";\n".join(importer.constraints({r["type"] for r in edges})) + ";\n", encoding="utf-8")
        queries = [importer.node_query(t) for t in sorted({r["label"] for r in nodes})]
        queries += [importer.edge_query(t) for t in sorted({r["type"] for r in edges})]
        (staging / "import.cypher").write_text("// Parameterized reference: $rows supplied by import_neo4j.py\n" + ";\n".join(queries) + ";\n", encoding="utf-8")
        graph_manifest = {"format": "spkg-neo4j-import-v1", "package_id": snapshot,
                          "source_package_id": manifest["package_id"], "target": "Neo4j 5.26 LTS",
                          "counts": {"nodes": len(nodes), "relationships": len(edges), "rejected_records": len(rejected)},
                          "files": {p.name: importer.sha256(p) for p in sorted(staging.iterdir())}}
        save(staging / "manifest.json", graph_manifest)
        importer.validate_package(staging)
        target = root / "neo4j"
        if target.is_symlink() or target.resolve().parent != root:
            raise ValueError("Unsafe graph output target")
        if target.exists():
            history = root / "_neo4j_history"
            if history.is_symlink() or history.resolve().parent != root:
                raise ValueError("Unsafe graph history")
            history.mkdir(exist_ok=True)
            target.rename(history / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
        staging.rename(target)
    for path in sorted(target.iterdir()):
        key = "neo4j_" + path.name.replace(".", "_").replace("-", "_")
        manifest["artifacts"][key] = path.relative_to(root).as_posix()
        manifest["artifact_sha256"][key] = importer.sha256(path)
    manifest.setdefault("quality", {})["neo4j_import"] = {
        "structurally_valid": True, "status": "partial" if rejected else "ready",
        "snapshot_id": snapshot, "counts": graph_manifest["counts"], "database_written": False,
        "live_import_verified": False}
    updated = root / ".manifest.neo4j.tmp"
    save(updated, manifest)
    updated.replace(original_manifest)
    return graph_manifest
