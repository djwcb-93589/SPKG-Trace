from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import yaml

from spkg_workflow.config import ConfigurationError, load_pipeline_config
from spkg_workflow.providers.openai_compatible import OpenAICompatibleClient, ProviderRequestError


class VllmProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "pipeline.yaml"
        self.env_file = self.root / ".env.local"
        self.env_file.write_text("", encoding="utf-8")
        self.payload = {"provider": {"backend": "vllm", "base_url": "http://127.0.0.1:8000/v1",
            "model": "deepseek-local", "auth_required": False, "json_mode": "prompt",
            "max_retries": 1, "timeout_seconds": 3}, "poi_mapping": {"max_tokens": 512, "temperature": 0.0}}
        self.config.write_text(yaml.safe_dump(self.payload), encoding="utf-8")
        # Keep Windows/Conda/OpenSSL runtime variables; isolate application configuration only.
        clean_env = {k: v for k, v in os.environ.items()
                     if not k.startswith(("SPKG_", "EDC_")) and k not in {"DEEPSEEK_API_KEY", "DS_TOKEN", "OPENAI_API_KEY", "OLD_KEY"}}
        clean_env["NO_PROXY"] = "127.0.0.1,localhost"
        env = patch.dict(os.environ, clean_env, clear=True)
        env.start()
        self.addCleanup(env.stop)

    def settings(self, required=True):
        return load_pipeline_config(self.config, self.env_file, require_api_key=required)

    def server(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, status, body):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self.server.requests.append((self.path, self.headers.get("Authorization"), None))
                if self.path != "/v1/models":
                    return self.respond(404, {"error": {"message": "bad route"}})
                self.respond(200, {"object": "list", "data": [{"id": "deepseek-local", "object": "model", "created": 0, "owned_by": "vllm"}]})

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                self.server.requests.append((self.path, self.headers.get("Authorization"), payload))
                if self.path != "/v1/chat/completions":
                    return self.respond(404, {"error": {"message": "bad route"}})
                self.respond(200, {"id": "mock-vllm", "object": "chat.completion", "created": 0,
                    "model": payload["model"], "choices": [{"index": 0, "finish_reason": self.server.finish,
                    "message": {"role": "assistant", "content": self.server.content,
                                "reasoning": "not an answer", "reasoning_content": "not an answer"}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}})
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.requests = []
        server.content = '{"ok":true}'
        server.finish = "stop"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        os.environ["SPKG_VLLM_BASE_URL"] = f"http://127.0.0.1:{server.server_port}/v1"
        client = OpenAICompatibleClient(self.settings().provider)
        self.addCleanup(client._client.close)
        return server, client

    def test_no_cloud_endpoint_key_or_model_leaks(self):
        with patch.dict(os.environ, {"SPKG_OPENAI_BASE_URL": "https://cloud.invalid",
            "DEEPSEEK_API_KEY": "old-cloud-secret", "OPENAI_API_KEY": "old-openai-secret",
            "SPKG_FIELD_SEMANTICS_MODEL": "cloud-a", "SPKG_POI_MAPPING_MODEL": "cloud-b"}):
            settings = self.settings()
            self.assertEqual(settings.provider.api_key, "EMPTY")
            self.assertEqual(settings.provider.base_url, "http://127.0.0.1:8000/v1")
            self.assertEqual(set(settings.provider.models.values()), {"deepseek-local"})
            self.assertNotIn("secret", json.dumps(settings.public_summary()))
            self.assertEqual(settings.raw["parameter_extraction"]["max_tokens"], 512)
            self.assertEqual(settings.raw["parameter_extraction"]["max_workers"], 2)

    def test_auth_required_and_secret_hidden(self):
        os.environ["SPKG_VLLM_AUTH_REQUIRED"] = "true"
        with self.assertRaises(ConfigurationError):
            self.settings()
        os.environ["SPKG_VLLM_API_KEY"] = "local-secret"
        self.assertEqual(self.settings().provider.api_key, "local-secret")
        self.assertNotIn("local-secret", json.dumps(self.settings().public_summary()))
        self.assertNotIn("local-secret", json.dumps(self.settings().provider.request_signature()))

    def test_address_validation(self):
        os.environ["SPKG_VLLM_BASE_URL"] = "http://127.0.0.1:9000/"
        self.assertEqual(self.settings().provider.base_url, "http://127.0.0.1:9000/v1")
        for value in ("http://host:8000/v1/chat/completions", "ftp://host/v1", "http://name:secret@host/v1", "http://host/v1?key=secret"):
            with self.subTest(value=value):
                os.environ["SPKG_VLLM_BASE_URL"] = value
                with self.assertRaises(ConfigurationError):
                    self.settings()

    def test_request_options_and_cache_signature(self):
        original = self.settings().provider.request_signature()
        os.environ["SPKG_VLLM_CHAT_TEMPLATE_KWARGS"] = '{"thinking":false}'
        changed = self.settings()
        self.assertNotEqual(original, changed.provider.request_signature())
        self.assertEqual(changed.provider.chat_template_kwargs, {"thinking": False})
        for name, value in (("SPKG_VLLM_CHAT_TEMPLATE_KWARGS", '{"password":"secret"}'),
                            ("SPKG_VLLM_MAX_WORKERS", "0"), ("SPKG_VLLM_JSON_MODE", "unknown"),
                            ("SPKG_VLLM_AUTH_REQUIRED", "perhaps")):
            with self.subTest(name=name), patch.dict(os.environ, {name: value}), self.assertRaises(ConfigurationError):
                self.settings()

    def test_http_all_four_stages_use_vllm_chat(self):
        server, client = self.server()
        for stage in ("librelog", "field_semantics", "poi_mapping", "parameter_extraction"):
            self.assertEqual(client.generate_json([{"role": "user", "content": "Return JSON"}], stage=stage), {"ok": True})
        self.assertEqual(len(server.requests), 4)
        for path, auth, body in server.requests:
            self.assertEqual(path, "/v1/chat/completions")
            self.assertEqual(auth, "Bearer EMPTY")
            self.assertEqual(body["model"], "deepseek-local")
            self.assertNotIn("response_format", body)
            self.assertNotIn("chat_template_kwargs", body)

    def test_http_auth_json_mode_and_thinking_kwarg(self):
        os.environ.update(SPKG_VLLM_AUTH_REQUIRED="true", SPKG_VLLM_API_KEY="local-secret",
                          SPKG_VLLM_JSON_MODE="json_object", SPKG_VLLM_CHAT_TEMPLATE_KWARGS='{"thinking":false}')
        server, client = self.server()
        client.generate_json([{"role": "user", "content": "Return JSON"}], stage="field_semantics")
        _, auth, body = server.requests[0]
        self.assertEqual(auth, "Bearer local-secret")
        self.assertEqual(body["response_format"], {"type": "json_object"})
        self.assertEqual(body["chat_template_kwargs"], {"thinking": False})
        self.assertNotIn("local-secret", json.dumps(client.usage_summary()))

    def test_reasoning_and_json_fence_handling(self):
        server, client = self.server()
        server.content = '<think>internal</think>\n```json\n{"ok":true}\n```'
        self.assertEqual(client.generate_json([{"role": "user", "content": "JSON"}], stage="poi_mapping"), {"ok": True})
        for content, finish in ((None, "stop"), ("<think>unfinished", "stop"), ("<think>x</think>", "stop"), ('{"ok":true}', "length")):
            server.content, server.finish = content, finish
            with self.subTest(content=content), self.assertRaises(ProviderRequestError):
                client.generate_json([{"role": "user", "content": "JSON"}], stage="poi_mapping")

    def test_model_listing_and_synthetic_check(self):
        server, client = self.server()
        self.assertFalse(client.check_connection()["generation_checked"])
        self.assertEqual(len(server.requests), 1)
        self.assertTrue(client.check_connection(generate=True)["json_response_ok"])
        self.assertEqual(len(server.requests), 3)
        client.settings = replace(client.settings, models={"librelog": "missing-model"})
        with self.assertRaisesRegex(ProviderRequestError, "absent"):
            client.check_connection()

    def test_environment_file_and_explicit_overrides(self):
        self.env_file.write_text('SPKG_VLLM_MODEL=from-file\nSPKG_VLLM_MAX_WORKERS=1\n', encoding="utf-8")
        self.assertEqual(set(self.settings().provider.models.values()), {"from-file"})
        os.environ["SPKG_VLLM_MODEL"] = "from-process"
        self.assertEqual(set(self.settings().provider.models.values()), {"from-process"})

    def test_explicit_legacy_branch_still_works(self):
        self.payload["provider"].update(backend="openai_compatible", base_url="https://cloud.invalid/v1",
            api_key_envs=["OLD_KEY"], models={"librelog": "cloud", "field_semantics": "cloud", "poi_mapping": "cloud"})
        self.config.write_text(yaml.safe_dump(self.payload), encoding="utf-8")
        os.environ["OLD_KEY"] = "old-key"
        self.assertEqual(self.settings().provider.api_key, "old-key")
        self.assertEqual(self.settings().provider.models["parameter_extraction"], "cloud")


if __name__ == "__main__":
    unittest.main()
