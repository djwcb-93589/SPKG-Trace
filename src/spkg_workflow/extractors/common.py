from __future__ import annotations

import re
from typing import Iterable

from spkg_workflow.contracts import JsonValue


KEY_VALUE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*"
    r'(?:"(?P<double>(?:\\.|[^"])*)"|\'(?P<single>(?:\\.|[^\'])*)\'|(?P<bare>[^\s,;]+))'
)


def normalize_key(key: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", key.strip()).strip("_").lower()
    return value


def clean_value(value: str | None) -> str:
    if value is None:
        return ""
    result = value.strip()
    if len(result) >= 2 and result[0] == result[-1] and result[0] in {"'", '"'}:
        result = result[1:-1]
    return result.strip().rstrip(",;")


def extract_key_values(text: str, *, max_depth: int = 3) -> dict[str, str]:
    """Extract outer and recursively nested key/value pairs from a log line."""
    values: dict[str, str] = {}
    pending = [text]
    seen_payloads: set[str] = set()
    depth = 0
    while pending and depth < max_depth:
        next_pending: list[str] = []
        for payload in pending:
            if payload in seen_payloads:
                continue
            seen_payloads.add(payload)
            for match in KEY_VALUE_RE.finditer(payload):
                key = normalize_key(match.group("key"))
                raw = match.group("double")
                if raw is None:
                    raw = match.group("single")
                if raw is None:
                    raw = match.group("bare")
                value = clean_value(raw)
                values.setdefault(key, value)
                if "=" in value:
                    next_pending.append(value)
        pending = next_pending
        depth += 1
    return values


def set_aliases(
    target: dict[str, JsonValue], value: JsonValue, names: Iterable[str]
) -> None:
    if value in (None, ""):
        return
    for name in names:
        target.setdefault(normalize_key(name), value)


def normalize_outcome(value: str | None) -> str:
    normalized = clean_value(value).lower()
    if normalized in {"success", "successful", "succeeded", "yes", "ok", "accepted"}:
        return "success"
    if normalized in {
        "failure",
        "failed",
        "no",
        "denied",
        "refused",
        "error",
        "timeout",
        "timed_out",
    }:
        return "failure"
    if normalized:
        return normalized
    return ""


def split_endpoint(value: str) -> tuple[str, str]:
    text = clean_value(value)
    if not text:
        return "", ""
    if text.startswith("[") and "]:" in text:
        host, port = text.rsplit(":", 1)
        return host[1:-1], port
    if ":" in text:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            return host, port
    return text, ""
