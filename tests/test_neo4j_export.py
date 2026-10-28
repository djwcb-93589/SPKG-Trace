import copy
import csv
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

from spkg_workflow import neo4j_importer as importer
from spkg_workflow.config import PROJECT_ROOT
from spkg_workflow.stages.neo4j_export import compile_condition, compile_schema, export_package, matches, materialize, save


class MemoryDriver:
    """Exercises batching, retry/idempotent IDs and endpoint accounting, NOT Neo4j syntax."""
    def __init__(self):
        self.nodes = {}
        self.edges = {}
        self.calls = []

    def execute_query(self, query, parameters_=None, database_=None):
        self.calls.append((query, parameters_, database_))
        if query.startswith("CREATE CONSTRAINT"):
            return [], None, None
        rows = parameters_["rows"]
        if "MERGE (n:" in query:
            self.nodes.update({r["id"]: r for r in rows})
        elif "MERGE (a)-" in query:
            rows = [r for r in rows if r["start_id"] in self.nodes and r["end_id"] in self.nodes]
            self.edges.update({r["id"]: r for r in rows})
        elif "MATCH (n:" in query:
            rows = [r for r in rows if r["id"] in self.nodes]
        else:
            rows = [r for r in rows if r["id"] in self.edges]
        return [{"processed": len(rows)}], None, None


class GraphExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "schema").mkdir()
        (self.root / "artifacts").mkdir()
        self.poi = self.root / "schema/poi.csv"
        self.poi.write_text('host,Host\npid,Process\nuser,Account\nevent_type,Event\n', encoding="utf-8")
        self.relations = self.root / "schema/relations.csv"
        self.relations.write_text(
            'subject_type,subject_id_source,predicate,object_type,object_id_source,edge_properties,condition\n'
            'Process,pid,RUNS_ON,Host,host,event_type,pid not null AND host not null\n'
            'User,user,STARTS,Process,pid,event_type,user not null AND event_type indicates su\n', encoding="utf-8")
        self.policy_path = self.root / "policy.yaml"
        self.policy = {"version": 1, "node_types": {"Host": {"scope": "dataset"}, "Process": {"scope": "event"},
                         "User": {"scope": "host"}}, "indicates": {"event_type": {"su": ["su_session"]}}}
        self.policy_path.write_text(yaml.safe_dump(self.policy), encoding="utf-8")
        self.rows = [self.record(1), self.record(2)]
        self.write_source()

    def record(self, line):
        return {"dataset_id": "demo", "line_id": line, "template_id": "tpl", "timestamp": "Jan 16 01:02:03",
                "original_content": 'host su[12]: user="甲,乙"\nextra', "status": "ok", "metadata": {"log_source": "auth"},
                "canonical_parameters": {"host": "server1", "pid": "12", "user": "甲,乙", "event_type": "su_session"},
                "field_evidence": {"user": {"evidence": 'user="甲,乙"'}}}

    def write_source(self):
        path = self.root / "artifacts/parameters.jsonl"
        path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in self.rows), encoding="utf-8")
        save(self.root / "manifest.json", {"record_type": "knowledge_package_manifest", "package_id": "demo-1", "dataset_id": "demo",
            "artifacts": {"parameters_jsonl": "artifacts/parameters.jsonl"},
            "artifact_sha256": {"parameters_jsonl": importer.sha256(path)},
            "schema_assets": [{"kind": kind, "relative_path": str(p.relative_to(self.root)), "sha256": importer.sha256(p)}
                              for kind, p in (("poi", self.poi), ("relation", self.relations))],
            "provenance": {"raw_log_sha256": "a" * 64}, "quality": {"processing_status": "complete"}})

    def export(self):
        return export_package(self.root, self.policy_path)

    def test_conditions_are_closed_and_exact(self):
        allowed = {"user", "event_type", "pid"}
        clauses = compile_condition("user not null AND event_type indicates su AND pid != '-'", allowed, self.policy["indicates"])
        self.assertTrue(matches(clauses, {"user": "alice", "event_type": "su_session", "pid": "12"}))
        self.assertFalse(matches(clauses, {"user": "alice", "event_type": "sudo_cmd", "pid": "12"}))
        for value in ("x", "", None):
            self.assertFalse(matches(clauses, {"user": "alice", "event_type": value, "pid": "12"}))
        self.assertTrue(matches(compile_condition("pid is null AND event_type in (a,b)", allowed, {}), {"event_type": "b"}))
        self.assertTrue(matches(compile_condition("event_type == login", allowed, {}), {"event_type": "login"}))
        for text in ("pid not null OR user not null", "missing = x", "event_type indicates unknown", "pid = __import__('os')"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                compile_condition(text, allowed, self.policy["indicates"])

    def test_all_bundled_schemas_compile(self):
        policy = yaml.safe_load((PROJECT_ROOT / "configs/graph_export.yaml").read_text(encoding="utf-8"))
        for name in ("auth", "audit", "apache", "dns", "vpn"):
            with self.subTest(name=name):
                schema = compile_schema(PROJECT_ROOT / f"configs/poi/{name}.csv", PROJECT_ROOT / f"configs/graph_schema/{name}_relations.csv", policy)
                self.assertGreater(len(schema["rules"]), 0)

    def test_unknown_identity_defaults_to_event_and_invalid_types_fail_closed(self):
        policy = copy.deepcopy(self.policy)
        del policy["node_types"]["Process"]
        schema = compile_schema(self.poi, self.relations, policy)
        self.assertEqual(schema['identity_policy']['node_types']['Process'], {'scope': 'event'})
        self.assertNotIn('Process', policy['node_types'])
        self.assertIn('Process', schema['warnings'][0])
        policy['node_types']['Process'] = {'scope': 'typo'}
        with self.assertRaises(ValueError):
            compile_schema(self.poi, self.relations, policy)
        for value in ("User`) DELETE n //", "", "A B"):
            with self.assertRaises(ValueError):
                importer.node_query(value)

    def custom_schema(self, scope=''):
        self.poi.write_text('client,Client\nservice,Service\naction,Action\n', encoding='utf-8')
        with self.relations.open('w', encoding='utf-8', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['subject_type', 'subject_id_source', 'predicate', 'object_type',
                             'object_id_source', 'edge_properties', 'condition', 'subject_scope', 'object_scope'])
            writer.writerow(['Customer', 'client', 'USES', 'Application', 'service', 'action',
                             'action in (login,logout)', scope, scope])
        for row in self.rows:
            row['canonical_parameters'] = {'client': 'alice', 'service': 'portal', 'action': 'login'}
        self.write_source()

    def test_custom_pair_exports_without_policy_registration(self):
        self.custom_schema()
        before = self.policy_path.read_bytes()
        self.export()
        _, nodes, edges = importer.validate_package(self.root / 'neo4j')
        self.assertEqual(sum(n['label'] == 'Customer' for n in nodes), 2)
        self.assertEqual(sum(n['label'] == 'Application' for n in nodes), 2)
        self.assertEqual(sum(e['type'] == 'USES' for e in edges), 2)
        self.assertEqual(len(importer.read_json(self.root / 'neo4j/validation.json')['schema_warnings']), 2)
        self.assertEqual(before, self.policy_path.read_bytes())

    def test_csv_scope_controls_merging(self):
        for scope, count in [('event', 2), ('dataset', 1), ('host', 1), ('global', 1)]:
            with self.subTest(scope=scope):
                self.custom_schema(scope)
                self.export()
                _, nodes, edges = importer.validate_package(self.root / 'neo4j')
                self.assertEqual(sum(n['label'] == 'Customer' for n in nodes), count)
                self.assertEqual(sum(e['type'] == 'USES' for e in edges), 2)

    def test_csv_scope_conflicts_and_typos_rejected(self):
        self.custom_schema('datset')
        with self.assertRaisesRegex(ValueError, 'scope'):
            compile_schema(self.poi, self.relations, self.policy)
        self.custom_schema('dataset')
        with self.relations.open('a', encoding='utf-8', newline='') as stream:
            csv.writer(stream).writerow(['Customer', 'client', 'OTHER', 'Application', 'service', '',
                                        'client not null', 'event', 'dataset'])
        with self.assertRaisesRegex(ValueError, '冲突'):
            compile_schema(self.poi, self.relations, self.policy)

    def test_unregistered_alias_has_csv_remediation(self):
        with self.assertRaisesRegex(ValueError, r'event_type in \(value1,value2\)'):
            compile_condition('event_type indicates custom_login', {'event_type'}, {})

    def test_explicit_scope_overrides_builtin_without_mutating_policy(self):
        self.custom_schema('dataset')
        self.relations.write_text(self.relations.read_text(encoding='utf-8').replace('Customer', 'Process'), encoding='utf-8')
        schema = compile_schema(self.poi, self.relations, self.policy)
        self.assertEqual(schema['identity_policy']['node_types']['Process']['scope'], 'dataset')
        self.assertEqual(self.policy['node_types']['Process']['scope'], 'event')

    def test_custom_schema_through_knowledge_package_stage(self):
        self.custom_schema('dataset')
        self.test_workflow_knowledge_stage_generates_import_files()
        _, nodes, edges = importer.validate_package(self.root / 'output/neo4j')
        self.assertEqual(sum(n['label'] == 'Customer' for n in nodes), 1)
        self.assertEqual(sum(e['type'] == 'USES' for e in edges), 2)

    def test_reserved_types_still_rejected(self):
        self.custom_schema()
        self.relations.write_text(self.relations.read_text(encoding='utf-8').replace('Customer', 'LogEvent'), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'identity policy'):
            compile_schema(self.poi, self.relations, self.policy)

    def test_export_complete_and_preserves_events(self):
        result = self.export()
        manifest, nodes, edges = importer.validate_package(self.root / "neo4j")
        self.assertEqual(result, manifest)
        self.assertEqual(sum(n["label"] == "LogEvent" for n in nodes), 2)
        self.assertEqual(sum(n["label"] == "Process" for n in nodes), 2)
        self.assertEqual(sum(n["label"] == "User" for n in nodes), 1)
        self.assertEqual(sum(e["type"] == "STARTS" for e in edges), 2)
        event = next(n for n in nodes if n["label"] == "LogEvent")
        self.assertIn('甲,乙', event["properties"]["original_content"])
        self.assertEqual(event["properties"]["timestamp_raw"], "Jan 16 01:02:03")
        self.assertEqual(event["properties"]["time_precision"], "raw_unresolved")
        with (self.root / "neo4j/nodes.csv").open(encoding="utf-8-sig", newline="") as stream:
            csv_nodes = list(csv.DictReader(stream))
        self.assertEqual(len(csv_nodes), len(nodes))
        self.assertTrue(any(json.loads(n["properties_json"]).get("original_content") == self.rows[0]["original_content"] for n in csv_nodes))
        sealed = importer.read_json(self.root / "manifest.json")
        for name, path in sealed["artifacts"].items():
            self.assertEqual(importer.sha256(self.root / path), sealed["artifact_sha256"][name])

    def test_deterministic_reexport_archives_previous(self):
        one = self.export()
        two = self.export()
        self.assertEqual(one, two)
        self.assertEqual(len(list((self.root / "_neo4j_history").iterdir())), 1)

    def test_partial_rows_quarantined(self):
        self.rows[1]["status"] = "uncertain"
        self.write_source()
        result = self.export()
        self.assertEqual(result["counts"]["rejected_records"], 1)
        self.assertEqual(importer.read_json(self.root / "manifest.json")["quality"]["neo4j_import"]["status"], "partial")
        with patch.dict("os.environ", {}, clear=True), self.assertRaisesRegex(ValueError, "rejected records"):
            importer.main(["--package", str(self.root / "neo4j"), "--apply"])

    def test_tamper_and_path_escape_rejected(self):
        self.export()
        with (self.root / "neo4j/nodes.jsonl").open("a", encoding="utf-8") as stream:
            stream.write("{}\n")
        with self.assertRaisesRegex(ValueError, "modified"):
            importer.validate_package(self.root / "neo4j")
        manifest = importer.read_json(self.root / "neo4j/manifest.json")
        manifest["files"]["../policy.yaml"] = importer.sha256(self.policy_path)
        save(self.root / "neo4j/manifest.json", manifest)
        with self.assertRaises(ValueError):
            importer.validate_package(self.root / "neo4j")

    def test_bad_source_does_not_replace_existing_export(self):
        self.export()
        before = (self.root / "neo4j/manifest.json").read_bytes()
        self.poi.write_text("unexpected,Changed schema\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.export()
        self.assertEqual(before, (self.root / "neo4j/manifest.json").read_bytes())

    def test_duplicate_lines_fail(self):
        self.rows[1]["line_id"] = 1
        self.write_source()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.export()

    def test_missing_endpoints_never_generate_dangling_edges(self):
        self.rows[1]["canonical_parameters"]["pid"] = None
        self.write_source()
        self.export()
        _, nodes, edges = importer.validate_package(self.root / "neo4j")
        self.assertEqual(sum(e["type"] == "STARTS" for e in edges), 1)
        self.assertEqual(sum(n["label"] == "LogEvent" for n in nodes), 2)

    def test_standalone_validation_outside_project(self):
        self.export()
        result = subprocess.run([sys.executable, "-I", str(self.root / "neo4j/import_neo4j.py")],
                                cwd=self.root, capture_output=True, text=True, encoding="utf-8", timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["database_written"])

    def test_importer_batches_parameters_and_repeat_is_idempotent(self):
        self.export()
        _, nodes, edges = importer.validate_package(self.root / "neo4j")
        driver = MemoryDriver()
        for _ in range(2):
            result = importer.apply_package(driver, "test", nodes, edges, batch_size=1)
            self.assertEqual(result, {"nodes": len(nodes), "relationships": len(edges)})
        self.assertEqual(len(driver.nodes), len(nodes))
        self.assertEqual(len(driver.edges), len(edges))
        self.assertFalse(any("甲,乙" in query for query, _, _ in driver.calls))
        with self.assertRaises(ValueError):
            importer.apply_package(driver, "test", nodes, edges, batch_size=0)

    def test_changed_input_is_a_new_snapshot(self):
        before = self.export()["package_id"]
        self.rows[1]["canonical_parameters"]["user"] = "another"
        self.write_source()
        self.assertNotEqual(before, self.export()["package_id"])

    def test_workflow_knowledge_stage_generates_import_files(self):
        from spkg_workflow.stages.knowledge_package import build_knowledge_package
        settings = SimpleNamespace(raw={"knowledge_package": {"prepare_neo4j_import": True,
            "graph_export_policy": str(self.policy_path)}}, resolve_path=lambda value: Path(value))
        result = build_knowledge_package(settings=settings, package_dir=self.root / "output",
            package_id="demo-integration", dataset_id="demo", source_files=("input.log",),
            artifact_paths={"parameters_jsonl": self.root / "artifacts/parameters.jsonl"}, record_counts={"parameters": 2},
            poi_schema_path=self.poi, relation_schema_path=self.relations, poi_schema_id="demo", relation_schema_id="demo",
            provenance={"raw_log_sha256": "a" * 64})
        self.assertEqual(result.manifest.quality["neo4j_import"]["status"], "ready")
        self.assertFalse(result.manifest.neo4j_write_enabled)
        importer.validate_package(result.package_dir / "neo4j")

    def test_import_rejects_incompatible_property_types(self):
        for value in (2 ** 63, float('nan'), {"nested": 1}, ["list"]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                importer.check_properties({"value": value})
        self.assertTrue(importer.property_value(2 ** 63 - 1))

    def test_database_credentials_required_only_for_apply(self):
        self.export()
        with patch.dict("os.environ", {}, clear=True), self.assertRaisesRegex(ValueError, "NEO4J_URI"):
            importer.main(["--package", str(self.root / "neo4j"), "--apply"])


if __name__ == "__main__":
    unittest.main()
