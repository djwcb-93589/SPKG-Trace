from __future__ import annotations

import json
import re
import time
from threading import Lock
from typing import Any, Mapping, Sequence

from openai import OpenAI

from spkg_workflow.config import ProviderSettings


ChatMessage = Mapping[str, Any]


class ProviderRequestError(RuntimeError):
    """Raised after an OpenAI-compatible request exhausts its retries."""


def strip_reasoning_content(content: str) -> str:
    """Remove reasoning text emitted before a closing ``</think>`` marker."""
    marker = "</think>"
    marker_index = content.lower().rfind(marker)
    if marker_index >= 0:
        return content[marker_index + len(marker) :].lstrip()
    if "<think>" in content.lower():
        raise ValueError("Unfinished reasoning block; no final answer")
    return content.strip()


class OpenAICompatibleClient:
    """One credential-safe client shared by all LLM-backed workflow stages."""

    def __init__(self, settings: ProviderSettings):
        self.settings = settings
        self._lock = Lock()
        self._calls: list[dict[str, Any]] = []
        self._client = OpenAI(
            api_key=settings.api_key,
            base_url=settings.base_url.rstrip("/"),
            timeout=settings.timeout_seconds,
            max_retries=0,
        )

    def _extra_body(self) -> dict[str, Any] | None:
        if self.settings.chat_template_kwargs:
            return {"chat_template_kwargs": dict(self.settings.chat_template_kwargs)}
        # Different DeepSeek templates use different switches. Do not assume Qwen's switch.
        if self.settings.backend == "vllm":
            return None
        if not self.settings.disable_thinking:
            return None
        return {"chat_template_kwargs": {"enable_thinking": False}}

    def generate(
        self,
        messages: Sequence[ChatMessage],
        *,
        stage: str,
        max_tokens: int = 1024,
        temperature: float | None = None,
        json_object: bool = False,
    ) -> str:
        model = self.settings.models.get(stage)
        if not model:
            raise ProviderRequestError(f"No model is configured for stage: {stage}")

        request: dict[str, Any] = {
            "model": model,
            "messages": list(messages),
            "max_tokens": max_tokens,
            "temperature": (
                self.settings.temperature if temperature is None else temperature
            ),
        }
        if json_object and self.settings.json_mode == "json_object":
            request["response_format"] = {"type": "json_object"}
        extra_body = self._extra_body()
        if extra_body:
            request["extra_body"] = extra_body

        last_error: Exception | None = None
        for attempt in range(1, self.settings.max_retries + 1):
            started = time.monotonic()
            try:
                response = self._client.chat.completions.create(**request)
                usage = response.usage
                with self._lock:
                    self._calls.append({"stage": stage, "model": model, "attempt": attempt,
                        "seconds": round(time.monotonic() - started, 3), "status": "response",
                        "finish_reason": response.choices[0].finish_reason,
                        "prompt_tokens": getattr(usage, "prompt_tokens", 0) or 0,
                        "completion_tokens": getattr(usage, "completion_tokens", 0) or 0})
                if response.choices[0].finish_reason == "length":
                    raise ValueError("Provider output was truncated by the token limit")
                content = response.choices[0].message.content
                if isinstance(content, list):
                    content = "".join(
                        str(item.get("text", ""))
                        for item in content
                        if isinstance(item, dict) and item.get("type") == "text"
                    )
                if not isinstance(content, str) or not content.strip():
                    raise ValueError("Provider returned an empty response")
                final = strip_reasoning_content(content)
                if not final.strip():
                    raise ValueError("Provider returned reasoning without a final answer")
                return final
            except Exception as exc:  # provider SDK exposes several error classes
                last_error = exc
                with self._lock:
                    self._calls.append({"stage": stage, "model": model, "attempt": attempt,
                        "seconds": round(time.monotonic() - started, 3), "status": "error",
                        "error_type": type(exc).__name__})
                if attempt >= self.settings.max_retries:
                    break
                time.sleep(min(2 ** (attempt - 1), 8))

        error_type = type(last_error).__name__ if last_error else "UnknownError"
        raise ProviderRequestError(
            f"Provider request failed after {self.settings.max_retries} attempts "
            f"({error_type}); credentials were not included in this error"
        ) from last_error

    def generate_json(
        self,
        messages: Sequence[ChatMessage],
        *,
        stage: str,
        max_tokens: int = 1024,
        temperature: float | None = None,
    ) -> dict[str, Any]:
        raw = self.generate(
            messages,
            stage=stage,
            max_tokens=max_tokens,
            temperature=temperature,
            json_object=True,
        )
        fence = re.fullmatch(r"```(?:json)?\s*\n?(.*?)\n?```", raw.strip(), flags=re.S | re.I)
        if fence:
            raw = fence[1].strip()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProviderRequestError(
                f"Provider returned invalid JSON for stage {stage}: {exc.msg}"
            ) from exc
        if not isinstance(payload, dict):
            raise ProviderRequestError(
                f"Provider JSON for stage {stage} must be an object"
            )
        return payload

    def check_connection(self, *, generate: bool = False, max_tokens: int = 1024) -> dict[str, Any]:
        """Explicit diagnostic: model listing, optionally a tiny synthetic JSON request."""
        if max_tokens < 1:
            raise ValueError("max_tokens must be positive")
        try:
            available = [item.id for item in self._client.models.list().data]
        except Exception as exc:
            raise ProviderRequestError(f"Model listing failed ({type(exc).__name__}); check endpoint, reachability and auth") from None
        missing = sorted(set(self.settings.models.values()) - set(available))
        if missing:
            raise ProviderRequestError("Configured model is absent from /v1/models: " + ", ".join(missing))
        report = {"backend": self.settings.backend, "base_url": self.settings.base_url,
                  "available_models": available, "configured_models": self.settings.models,
                  "model_listing_ok": True, "generation_checked": generate}
        if generate:
            for model in sorted(set(self.settings.models.values())):
                stage = next(k for k, v in self.settings.models.items() if v == model)
                result = self.generate_json([{"role": "user", "content": 'Return only this JSON object, no explanation: {"ok": true}'}],
                                            stage=stage, max_tokens=max_tokens, temperature=0.0)
                if result.get("ok") is not True:
                    raise ProviderRequestError("Synthetic JSON response check failed")
            report["json_response_ok"] = True
        return report

    def usage_summary(self) -> dict[str, Any]:
        with self._lock:
            calls = list(self._calls)
        by_stage: dict[str, dict[str, int]] = {}
        for call in calls:
            stage = by_stage.setdefault(call["stage"], {"responses": 0, "errors": 0,
                                       "prompt_tokens": 0, "completion_tokens": 0})
            stage["responses" if call["status"] == "response" else "errors"] += 1
            stage["prompt_tokens"] += call.get("prompt_tokens", 0)
            stage["completion_tokens"] += call.get("completion_tokens", 0)
        return {"by_stage": by_stage, "calls": calls}
