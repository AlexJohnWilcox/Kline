import httpx
import structlog

from config.settings import settings

logger = structlog.get_logger()


class OllamaError(Exception):
    pass


class OllamaClient:
    """Async wrapper around the Ollama REST API."""

    def __init__(self, base_url: str, model: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=5.0),
        )

    async def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        json_mode: bool = False,
        temperature: float = 0.3,
    ) -> str:
        """Generate a completion from Ollama (non-streaming)."""
        body: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            body["system"] = system
        if json_mode:
            body["format"] = "json"

        try:
            resp = await self._http.post(f"{self.base_url}/api/generate", json=body)
            resp.raise_for_status()
            return resp.json()["response"]
        except httpx.HTTPStatusError as e:
            raise OllamaError(f"Ollama HTTP {e.response.status_code}") from e
        except httpx.ConnectError as e:
            raise OllamaError("Ollama not reachable") from e
        except Exception as e:
            raise OllamaError(str(e)) from e

    async def is_available(self) -> bool:
        """Check if Ollama is reachable."""
        try:
            resp = await self._http.get(f"{self.base_url}/api/tags", timeout=3.0)
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self._http.aclose()


_client: OllamaClient | None = None


def get_ollama_client() -> OllamaClient:
    """Get or create the Ollama client singleton."""
    global _client
    if _client is None:
        _client = OllamaClient(
            base_url=settings.ollama_url,
            model=settings.ollama_model,
            timeout=settings.ollama_timeout,
        )
        logger.info("ollama_client_created", url=settings.ollama_url, model=settings.ollama_model)
    return _client


async def close_ollama_client() -> None:
    """Close the Ollama client."""
    global _client
    if _client is not None:
        await _client.close()
        _client = None
        logger.info("ollama_client_closed")
