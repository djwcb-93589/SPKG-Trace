"""Shared model-provider adapters."""

from .openai_compatible import OpenAICompatibleClient, ProviderRequestError

__all__ = ["OpenAICompatibleClient", "ProviderRequestError"]
