"""
SPECTER LLM Router
Universal adapter — NVIDIA, OpenRouter, Ollama, OpenAI, Anthropic.
Any provider that supports the OpenAI-compatible API format.
"""

import os
import yaml
import time
import logging
from typing import List, Optional, Tuple, Dict, Any

from openai import OpenAI, APIError, RateLimitError, APITimeoutError

logger = logging.getLogger("specter.router")


class LLMRouter:
    """Wraps an OpenAI‑compatible client and provides retry logic.

    Attributes:
        config: Loaded configuration dictionary.
        client: Underlying OpenAI client instance.
        model: Model identifier to use.
        provider: Human‑readable provider name.
        max_tokens: Maximum tokens per request.
        temperature: Sampling temperature.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(self, config_path: str = "config.yaml") -> None:
        """Load configuration and initialise the LLM client.

        Args:
            config_path: Path to the YAML configuration file.
        """
        with open(config_path, "r") as f:
            self.config: Dict[str, Any] = yaml.safe_load(f)

        # Environment variables override config file
        api_key: str = os.getenv("SPECTER_API_KEY") or self.config.get("api_key", "")
        base_url: str = os.getenv("SPECTER_BASE_URL") or self.config.get("base_url", "")
        self.model: str = os.getenv("SPECTER_MODEL") or self.config.get("model", "")
        self.provider: str = self.config.get("provider", "unknown")

        self.max_tokens: int = self.config.get("max_tokens", 4096)
        self.temperature: float = self.config.get("temperature", 0.2)
        self.timeout: int = self.config.get("request_timeout", 30)

        if not api_key:
            raise ValueError("No API key found. Set api_key in config.yaml or SPECTER_API_KEY env var.")

        self.client = OpenAI(api_key=api_key, base_url=base_url, timeout=self.timeout)

    # ------------------------------------------------------------------
    def chat(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        retries: int = 3,
        backoff: float = 5.0,
    ) -> str:
        """Send a chat request to the LLM with retry handling.

        Args:
            messages: List of role/content dictionaries.
            system_prompt: Optional system message.
            retries: Number of retry attempts on rate‑limit or timeout.
            backoff: Base back‑off seconds; multiplied by attempt index.

        Returns:
            The trimmed response text.
        """
        full_messages: List[Dict[str, str]] = []
        if system_prompt:
            full_messages.append({"role": "system", "content": system_prompt})
        full_messages.extend(messages)

        for attempt in range(retries):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=full_messages,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                )
                return resp.choices[0].message.content.strip()
            except RateLimitError:
                wait = backoff * (attempt + 1)
                logger.warning(f"Rate limited. Waiting {wait}s before retry {attempt+1}/{retries}…")
                time.sleep(wait)
            except APITimeoutError:
                logger.warning(f"Timeout on attempt {attempt+1}/{retries}. Retrying…")
                time.sleep(backoff)
            except APIError as e:
                logger.error(f"API error: {e}")
                return f"[LLM_ERROR] {e}"
            except Exception as e:  # Fallback for unexpected errors
                logger.error(f"Unexpected error: {e}")
                return f"[LLM_ERROR] {e}"
        return "[LLM_ERROR] Max retries exceeded."

    # ------------------------------------------------------------------
    def test_connection(self) -> Tuple[bool, str]:
        """Verify API key and connectivity by requesting a known token.

        Returns:
            A tuple ``(ok, message)`` where ``ok`` indicates success.
        """
        try:
            result = self.chat(
                messages=[{"role": "user", "content": "Reply with exactly the word: ONLINE"}]
            )
            if "[LLM_ERROR]" in result:
                return False, result
            return True, f"Connected — model responded: '{result[:60]}'"
        except Exception as e:
            return False, str(e)

    # ------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        """Return a small dictionary describing the current configuration."""
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.config.get("base_url"),
        }
