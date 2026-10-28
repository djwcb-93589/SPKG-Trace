from __future__ import annotations

from typing import Any, Mapping, Sequence

from spkg_workflow.providers import OpenAICompatibleClient


class LibreLogProviderAdapter:
    """Expose the API expected by the pinned original LibreLog parser."""

    def __init__(self, client: OpenAICompatibleClient):
        self.client = client

    def generate(
        self,
        messages: Sequence[Mapping[str, Any]],
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> str:
        return self.client.generate(
            messages,
            stage="librelog",
            max_tokens=max_tokens,
            temperature=temperature,
            json_object=True,
        )
