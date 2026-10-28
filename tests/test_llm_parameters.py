import copy
import csv
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import Mock

from spkg_workflow.config import ProviderSettings, WorkflowSettings, PROJECT_ROOT, load_pipeline_config
from spkg_workflow.contracts import (ContractError, ExtractedRecord, FieldMapping, FieldSemantic,
    ParsedLogRecord, TemplateFieldMapping, TemplateFieldSemantics, TemplateRecord)
from spkg_workflow.stages.field_semantics import parse_field_semantics
from spkg_workflow.stages.llm_parameters import LLMParameterExtractor
from spkg_workflow.stages.parameter_extraction import write_parameter_csv
from spkg_workflow.stages.parameter_validation import validate_response
from spkg_workflow.stages.poi_mapping import PoiSchema, map_template_fields
from spkg_workflow.stages.template_sampling import template_id_for_record


class QueueClient:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = 0

    def generate_json(self, *args, **kwargs):
        self.calls += 1
        return copy.deepcopy(self.responses.pop(0))


class LLMParameterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "dataset" / "05_parameters"
        self.row = ParsedLogRecord("new_app", 1, "", "buyer=alice", "buyer=alice",
                                   "e1", "buyer=<*>", "unused", "test.log")
        tid = template_id_for_record(self.row)
        self.template = TemplateRecord("new_app", tid, "e1", "buyer=<*>", "unused", 1,
                                       samples=("buyer=alice",))
        self.field = FieldSemantic("buyer_name", "Customer placing this order", extraction_kind="llm")
        self.semantics = TemplateFieldSemantics("new_app", tid, "unused", (self.field,))
        self.poi = PoiSchema("commerce", "test.csv", {"customer": "Customer placing the order"})
        self.mapping = TemplateFieldMapping("new_app", tid, "commerce", (
            FieldMapping("buyer_name", self.field.definition, "customer", self.poi.definitions["customer"], "mapped"),))
        self.payload = {"records": [{"line_id": 1, "fields": {"buyer_name": {
            "value": "alice", "evidence": "buyer=alice", "status": "literal"}}, "issues": []}]}
        provider = ProviderSettings("https://invalid.test", "test-only", 1, 1, 0.0, False,
                                    {k: "test-model" for k in ("field_semantics", "poi_mapping", "parameter_extraction")})
        self.settings = WorkflowSettings(PROJECT_ROOT, {"parameter_extraction": {
            "max_workers": 1, "batch_size": 1, "validation_retries": 1, "upstream_retries": 1}}, provider)

    def validate(self, payload):
        return validate_response(payload, [self.row], self.semantics, self.mapping, self.poi)

    def extract(self, client, **kwargs):
        engine = LLMParameterExtractor(settings=self.settings, poi_schema=self.poi, output_dir=self.directory, client=client)
        return engine.extract([kwargs.get("row", self.row)], [self.template],
                              [kwargs.get("semantics", self.semantics)], [kwargs.get("mapping", self.mapping)],
                              log_source="commerce", family="never_registered_before")

    def test_unknown_family_does_not_use_registry(self):
        with patch("spkg_workflow.extractors.registry.get_family_extractor", side_effect=AssertionError("legacy call")):
            result = self.extract(QueueClient(self.payload))
        self.assertEqual(result.records[0].canonical_parameters, {"customer": "alice"})

    def test_rejects_other_log_evidence(self):
        payload = copy.deepcopy(self.payload)
        payload["records"][0]["fields"]["buyer_name"]["evidence"] = "buyer=bob"
        with self.assertRaises(ContractError):
            self.validate(payload)

    def test_rejects_invented_literal(self):
        payload = copy.deepcopy(self.payload)
        payload["records"][0]["fields"]["buyer_name"]["value"] = "18209"
        with self.assertRaises(ContractError):
            self.validate(payload)

    def test_missing_value_stays_null(self):
        payload = copy.deepcopy(self.payload)
        payload["records"][0]["fields"]["buyer_name"] = {"value": None, "evidence": None, "status": "absent"}
        result = self.validate(payload)[0]
        self.assertIsNone(result.canonical_parameters["customer"])
        self.assertEqual(result.status, "ok")

    def test_rejects_identity_derivation(self):
        payload = copy.deepcopy(self.payload)
        payload["records"][0]["fields"]["buyer_name"].update(status="derived", reason="guess")
        with self.assertRaises(ContractError):
            self.validate(payload)

    def test_rejects_unknown_field_and_wrong_line_ids(self):
        for change in ("field", "line", "duplicate", "missing"):
            payload = copy.deepcopy(self.payload)
            if change == "field":
                payload["records"][0]["fields"]["surprise"] = {"value": "x"}
            elif change == "line":
                payload["records"][0]["line_id"] = 99
            elif change == "duplicate":
                payload["records"] *= 2
            else:
                payload["records"] = []
            with self.subTest(change=change), self.assertRaises(ContractError):
                self.validate(payload)

    def test_invalid_response_retries_and_retains_failure_row(self):
        result = self.extract(QueueClient({"records": []}, {"records": []}))
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].status, "error")
        self.assertEqual(len(result.errors), 1)
        self.assertIsNone(result.records[0].canonical_parameters["customer"])

    def test_cache_uses_actual_log_and_mapping_not_just_template(self):
        client = QueueClient(self.payload)
        self.extract(client)
        cached = self.extract(QueueClient())
        self.assertEqual(cached.metrics["cache_hits"], 1)
        row = replace(self.row, original_content="buyer=bob", content="buyer=bob")
        payload = copy.deepcopy(self.payload)
        payload["records"][0]["fields"]["buyer_name"].update(value="bob", evidence="buyer=bob")
        result = self.extract(QueueClient(payload), row=row)
        self.assertEqual(result.records[0].canonical_parameters["customer"], "bob")
        self.assertEqual(result.metrics["cache_hits"], 0)
        revised = replace(self.semantics, revision=2)
        result = self.extract(QueueClient(self.payload), semantics=revised)
        self.assertEqual(result.metrics["cache_hits"], 0)

    def test_upstream_feedback_revises_then_reextracts(self):
        payload = copy.deepcopy(self.payload)
        payload["records"][0]["issues"] = [{"kind": "mapping_conflict", "message": "Clarify buyer role", "evidence": "buyer=alice"}]
        with patch("spkg_workflow.stages.llm_parameters.extract_template_field_semantics", return_value=replace(self.semantics, revision=2)), \
             patch("spkg_workflow.stages.llm_parameters.map_template_fields", return_value=replace(self.mapping, revision=2)):
            result = self.extract(QueueClient(payload, self.payload))
        self.assertEqual(result.metrics["upstream_revisions"], 1)
        self.assertEqual(result.records[0].metadata["semantics_revision"], 2)
        self.assertEqual(result.records[0].status, "ok")
        self.assertEqual(result.semantics[0].metadata["upstream_feedback"][0]["line_id"], 1)
        engine = LLMParameterExtractor(settings=self.settings, poi_schema=self.poi,
            output_dir=self.directory, client=QueueClient())
        request = engine._request([self.row], self.template, result.semantics[0], result.mappings[0])
        self.assertEqual(request["role_context"][0]["issues"][0]["message"], "Clarify buyer role")

    def test_unresolved_template_quarantines_even_unsampled_rows(self):
        config = copy.deepcopy(self.settings.raw)
        config["parameter_extraction"].update(batch_size=2, upstream_retries=0)
        self.settings = replace(self.settings, raw=config)
        payload = copy.deepcopy(self.payload)
        payload["records"].append({**copy.deepcopy(payload["records"][0]), "line_id": 2})
        payload["records"][0]["issues"] = [{"kind": "mapping_conflict",
            "message": "Clarify buyer role", "evidence": "buyer=alice"}]
        engine = LLMParameterExtractor(settings=self.settings, poi_schema=self.poi,
            output_dir=self.directory, client=QueueClient(payload))
        result = engine.extract([self.row, replace(self.row, line_id=2)], [self.template],
            [self.semantics], [self.mapping], log_source="commerce")
        self.assertEqual([r.status for r in result.records], ["uncertain", "uncertain"])
        self.assertEqual(len(result.errors), 2)

    def test_non_ok_csv_is_quarantined(self):
        row = replace(self.validate(self.payload)[0], status="uncertain")
        target = self.directory / "parameters.csv"
        write_parameter_csv(target, [row], canonical_fields=self.poi.fields)
        with target.open(encoding="utf-8-sig") as handle:
            result = next(csv.DictReader(handle))
        self.assertEqual(result["customer"], "")
        self.assertEqual(result["record_status"], "uncertain")

    def test_semantics_do_not_bind_sample_constants(self):
        fields = parse_field_semantics({"fields": [{"source_field": "buyer_name", "definition": "buyer",
                                                  "examples": ["alice"]}]}, self.template)
        self.assertEqual(fields[0].extraction_kind, "llm")
        self.assertIsNone(fields[0].capture_index)

    def test_reviewer_output_is_validated_and_used(self):
        config = copy.deepcopy(self.settings.raw)
        config["parameter_extraction"]["semantic_review"] = True
        self.settings = replace(self.settings, raw=config)
        draft = copy.deepcopy(self.payload)
        draft["records"][0]["fields"]["buyer_name"].update(value=None, evidence=None, status="absent")
        client = QueueClient(draft, self.payload)
        result = self.extract(client)
        self.assertEqual(client.calls, 2)
        self.assertEqual(result.records[0].canonical_parameters["customer"], "alice")
        self.assertTrue(result.records[0].metadata["semantic_review"])

    def test_declared_vocabulary_cannot_be_bypassed_with_literal_status(self):
        self.semantics = replace(self.semantics, fields=(replace(self.field, value_kind="derived", allowed_values=("buyer",)),))
        with self.assertRaises(ContractError):
            self.validate(self.payload)

    def test_mapping_retries_unexplained_coverage_loss(self):
        semantics = replace(self.semantics, metadata={"poi_coverage": {"customer": {
            "status": "available", "source_fields": ["buyer_name"], "reason": "Explicit buyer name"}}})
        client = Mock()
        client.generate.side_effect = ["buyer_name -> NONE", "buyer_name -> customer"]
        result = map_template_fields(self.template, semantics, self.poi, settings=self.settings, client=client)
        self.assertEqual(result.mappings[0].canonical_field, "customer")
        self.assertEqual(client.generate.call_count, 2)

    def test_shared_model_and_request_settings(self):
        config = load_pipeline_config(require_api_key=False)
        self.assertEqual(config.provider.models["parameter_extraction"], config.provider.models["field_semantics"])
        self.assertEqual(config.provider.models["parameter_extraction"], config.provider.models["poi_mapping"])
        for name in ("temperature", "max_tokens"):
            self.assertEqual(config.raw["parameter_extraction"][name], config.raw["poi_mapping"][name])
            self.assertEqual(config.raw["field_semantics"][name], config.raw["poi_mapping"][name])

    def test_catalog_review_requires_every_target_assessment(self):
        from spkg_workflow.stages.catalog_review import review_parameter_catalog
        client = QueueClient({"issues": []}, {"assessments": [
            {"line_id": 1, "reason": "buyer identifies the customer"}], "issues": []})
        records = self.validate(self.payload)
        result = review_parameter_catalog(records, {self.template.template_id: self.semantics}, self.poi,
            settings=self.settings, client=client, output_dir=self.directory, round_index=0)
        self.assertEqual(client.calls, 2)
        self.assertEqual(result[0].status, "ok")

    def test_catalog_issue_marks_uncertain_without_replacing_values(self):
        from spkg_workflow.stages.catalog_review import review_parameter_catalog
        records = self.validate(self.payload)
        payload = {"assessments": [{"line_id": 1, "reason": "Needs a role review"}],
                   "issues": [{"line_id": 1, "kind": "mapping_conflict", "message": "Review buyer role",
                               "evidence": "buyer=alice", "related_evidence": []}]}
        result = review_parameter_catalog(records, {self.template.template_id: self.semantics}, self.poi,
            settings=self.settings, client=QueueClient(payload), output_dir=self.directory, round_index=0)
        self.assertEqual(result[0].status, "uncertain")
        self.assertEqual(result[0].canonical_parameters, records[0].canonical_parameters)
        self.assertEqual(result[0].metadata["upstream_issues"][0]["kind"], "mapping_conflict")

    def test_catalog_rejects_fabricated_related_evidence(self):
        from spkg_workflow.stages.catalog_review import review_parameter_catalog
        payload = {"assessments": [{"line_id": 1, "reason": "Needs a role review"}],
                   "issues": [{"line_id": 1, "kind": "mapping_conflict", "message": "Review buyer role",
                               "evidence": "buyer=alice", "related_evidence": [
                                   {"line_id": 1, "evidence": "buyer=bob"}]}]}
        with self.assertRaises(ContractError):
            review_parameter_catalog(self.validate(self.payload), {self.template.template_id: self.semantics}, self.poi,
                settings=self.settings, client=QueueClient(payload, payload), output_dir=self.directory, round_index=0)

    def test_catalog_feedback_revises_then_reextracts(self):
        config = copy.deepcopy(self.settings.raw)
        config["parameter_extraction"]["catalog_review"] = True
        self.settings = replace(self.settings, raw=config)
        audit = {"assessments": [{"line_id": 1, "reason": "Clarify role"}],
                 "issues": [{"line_id": 1, "kind": "mapping_conflict", "message": "Clarify buyer role",
                             "evidence": "buyer=alice"}]}
        clean = {"assessments": [{"line_id": 1, "reason": "Customer role agrees"}], "issues": []}
        with patch("spkg_workflow.stages.llm_parameters.extract_template_field_semantics", return_value=replace(self.semantics, revision=2)), \
             patch("spkg_workflow.stages.llm_parameters.map_template_fields", return_value=replace(self.mapping, revision=2)):
            result = self.extract(QueueClient(self.payload, audit, self.payload, clean))
        self.assertEqual(result.metrics["upstream_revisions"], 1)
        self.assertEqual(result.records[0].status, "ok")

    def test_reads_legacy_contract_without_changing_values(self):
        row = self.validate(self.payload)[0]
        payload = row.to_dict()
        payload["contract_version"] = "1.0"
        payload.pop("field_evidence")
        payload.pop("status")
        restored = ExtractedRecord.from_dict(payload)
        self.assertEqual(restored.canonical_parameters, row.canonical_parameters)
        self.assertEqual(restored.field_evidence, {})


if __name__ == "__main__":
    unittest.main()
