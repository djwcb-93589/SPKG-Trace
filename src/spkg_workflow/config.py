from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from dotenv import load_dotenv
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "pipeline.yaml"
DEFAULT_ENV_PATH = PROJECT_ROOT / ".env.local"


class ConfigurationError(RuntimeError):
    """Raised when a required workflow setting cannot be resolved."""


@dataclass(frozen=True)
class ProviderSettings:
    base_url: str
    api_key: str
    timeout_seconds: int
    max_retries: int
    temperature: float
    disable_thinking: bool
    models: dict[str, str]
    backend: str = "openai_compatible"
    json_mode: str = "json_object"
    chat_template_kwargs: dict[str, Any] = field(default_factory=dict)
    auth_required: bool = True

    def request_signature(self) -> dict[str, Any]:
        """Only non-secret request semantics, also used to invalidate old caches."""
        return {"protocol_revision": 2, "backend": self.backend, "base_url": self.base_url,
                "models": self.models, "json_mode": self.json_mode,
                "chat_template_kwargs": self.chat_template_kwargs,
                "disable_thinking": self.disable_thinking, "temperature": self.temperature}


@dataclass(frozen=True)
class WorkflowSettings:
    root: Path
    raw: dict[str, Any]
    provider: ProviderSettings

    def resolve_path(self, value: str | Path) -> Path:
        path = Path(value)
        return path.resolve() if path.is_absolute() else (self.root / path).resolve()

    def public_summary(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "provider": {
                "backend": self.provider.backend,
                "base_url": self.provider.base_url,
                "api_key_configured": bool(self.provider.api_key),
                "timeout_seconds": self.provider.timeout_seconds,
                "max_retries": self.provider.max_retries,
                "temperature": self.provider.temperature,
                "disable_thinking": self.provider.disable_thinking,
                "models": dict(self.provider.models),
                "auth_required": self.provider.auth_required,
                "json_mode": self.provider.json_mode,
                "chat_template_kwargs": dict(self.provider.chat_template_kwargs),
            },
        }


def _first_environment_value(names: Iterable[str]) -> str:
    for name in names:
        value = os.getenv(str(name), "").strip()
        if value:
            return value
    return ""


def _model_with_override(models: dict[str, Any], stage: str, env_name: str) -> str:
    value = os.getenv(env_name, "").strip() or str(models.get(stage, "")).strip()
    if not value:
        raise ConfigurationError(f"No model configured for stage: {stage}")
    return value


def _boolean(value, name):
    if isinstance(value, bool):
        return value
    if str(value).strip().lower() in {"1", "true", "yes"}:
        return True
    if str(value).strip().lower() in {"0", "false", "no"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


def load_pipeline_config(
    config_path: str | Path | None = None,
    env_path: str | Path | None = None,
    *,
    require_api_key: bool = True,
) -> WorkflowSettings:
    selected_env = Path(env_path).resolve() if env_path else DEFAULT_ENV_PATH
    if selected_env.exists():
        load_dotenv(selected_env, override=False)

    selected_config = Path(config_path).resolve() if config_path else DEFAULT_CONFIG_PATH
    if not selected_config.exists():
        raise ConfigurationError(f"Config file does not exist: {selected_config}")

    payload = yaml.safe_load(selected_config.read_text(encoding="utf-8")) or {}
    provider_raw = payload.get("provider") or {}
    backend = str(provider_raw.get("backend", "openai_compatible"))
    if backend not in {"vllm", "openai_compatible"}:
        raise ConfigurationError("provider.backend must be vllm or openai_compatible")
    if backend == "vllm":
        # Never send retained cloud keys to a local service or honor old cloud endpoint overrides.
        base_url = os.getenv("SPKG_VLLM_BASE_URL", "").strip() or str(provider_raw.get("base_url", "http://127.0.0.1:8000/v1"))
        api_key = os.getenv("SPKG_VLLM_API_KEY", "").strip()
        auth_required = _boolean(os.getenv("SPKG_VLLM_AUTH_REQUIRED", provider_raw.get("auth_required", False)), "auth_required")
        if not auth_required and not api_key:
            api_key = "EMPTY"  # SDK requires a nonempty string; unauthenticated vLLM ignores it.
    else:
        base_url = _first_environment_value(provider_raw.get("base_url_envs") or [])
        base_url = base_url or str(provider_raw.get("base_url", "")).strip()
        api_key = _first_environment_value(provider_raw.get("api_key_envs") or [])
        auth_required = True
    address = urlsplit(base_url)
    if address.scheme not in {"http", "https"} or not address.hostname or address.username or address.password or address.query or address.fragment:
        raise ConfigurationError("Use an HTTP(S) API base URL without credentials, query or fragment")
    if backend == "vllm":
        path = address.path.rstrip("/")
        if not path:
            base_url = base_url.rstrip("/") + "/v1"
        elif not path.endswith("/v1"):
            raise ConfigurationError("vLLM base URL must end in /v1 (not /chat/completions)")
    if require_api_key and auth_required and (not api_key or api_key == "EMPTY"):
        raise ConfigurationError(
            "No API key found. Configure one of: "
            + ("SPKG_VLLM_API_KEY" if backend == "vllm" else ", ".join(provider_raw.get("api_key_envs") or []))
        )

    model_raw = provider_raw.get("models") or {}
    models = {
        "librelog": _model_with_override(model_raw, "librelog", "SPKG_LIBRELOG_MODEL"),
        "field_semantics": _model_with_override(
            model_raw, "field_semantics", "SPKG_FIELD_SEMANTICS_MODEL"
        ),
        "poi_mapping": _model_with_override(
            model_raw, "poi_mapping", "SPKG_POI_MAPPING_MODEL"
        ),
    } if backend != "vllm" else dict.fromkeys(
        ("librelog", "field_semantics", "poi_mapping"),
        os.getenv("SPKG_VLLM_MODEL", "").strip() or str(provider_raw.get("model", "")).strip())
    if not all(models.values()):
        raise ConfigurationError("Set SPKG_VLLM_MODEL to the served model ID from GET /v1/models")
    # Parameter extraction shares the existing semantic-alignment model and request
    # settings; it intentionally has no independent model/environment override.
    if models["field_semantics"] != models["poi_mapping"]:
        raise ConfigurationError("Field semantics and POI mapping must use the same model")
    models["parameter_extraction"] = models["poi_mapping"]
    alignment_raw = payload.get("poi_mapping") or {}
    parameter_raw = payload.setdefault("parameter_extraction", {})
    semantics_raw = payload.setdefault("field_semantics", {})
    for name, default in (("temperature", 0.0), ("max_tokens", 4096)):
        parameter_raw[name] = alignment_raw.get(name, default)
        semantics_raw[name] = alignment_raw.get(name, default)

    kwargs = provider_raw.get("chat_template_kwargs") or {}
    if backend == "vllm" and os.getenv("SPKG_VLLM_CHAT_TEMPLATE_KWARGS", "").strip():
        try:
            kwargs = json.loads(os.environ["SPKG_VLLM_CHAT_TEMPLATE_KWARGS"])
        except ValueError:
            raise ConfigurationError("SPKG_VLLM_CHAT_TEMPLATE_KWARGS must be a JSON object") from None
    if not isinstance(kwargs, dict) or any(k not in {"thinking", "enable_thinking"} or not isinstance(v, bool) for k, v in kwargs.items()):
        raise ConfigurationError("chat_template_kwargs only accepts boolean thinking/enable_thinking switches")
    json_mode = (os.getenv("SPKG_VLLM_JSON_MODE", "").strip() if backend == "vllm" else "") or provider_raw.get("json_mode", "json_object")
    if json_mode not in {"prompt", "json_object"}:
        raise ConfigurationError("json_mode must be prompt or json_object")
    if backend == "vllm":
        parameter_raw["max_workers"] = int(os.getenv("SPKG_VLLM_MAX_WORKERS", parameter_raw.get("max_workers", 2)))
        if parameter_raw["max_workers"] < 1:
            raise ConfigurationError("SPKG_VLLM_MAX_WORKERS must be positive")
    timeout = int(os.getenv("SPKG_VLLM_TIMEOUT_SECONDS", provider_raw.get("timeout_seconds", 300))) if backend == "vllm" else int(provider_raw.get("timeout_seconds", 120))
    retries = int(provider_raw.get("max_retries", 5))
    if timeout < 1 or retries < 1:
        raise ConfigurationError("timeout_seconds and max_retries must be positive")

    provider = ProviderSettings(
        base_url=base_url,
        api_key=api_key,
        timeout_seconds=timeout,
        max_retries=retries,
        temperature=float(provider_raw.get("temperature", 0.0)),
        disable_thinking=_boolean(provider_raw.get("disable_thinking", False), "disable_thinking"),
        models=models,
        backend=backend, json_mode=json_mode, chat_template_kwargs=kwargs, auth_required=auth_required,
    )
    return WorkflowSettings(root=PROJECT_ROOT, raw=payload, provider=provider)
