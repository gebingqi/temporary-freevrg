from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterator

from core.config import AppConfig

try:
    from langfuse import Langfuse, get_client
    from langfuse.langchain import CallbackHandler
except ImportError:  # pragma: no cover - optional runtime dependency
    Langfuse = None
    get_client = None
    CallbackHandler = None


def _sanitize(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return {key: _sanitize(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _sanitize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    return value


class _NoOpObservation:
    def update(self, **_: Any) -> None:
        return None


@contextmanager
def _noop_context() -> Iterator[_NoOpObservation]:
    yield _NoOpObservation()


class Observability:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._client = self._build_client()

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def flush(self) -> None:
        if self._client is None:
            return
        self._client.flush()

    def callback_handler(self) -> Any | None:
        if self._client is None or CallbackHandler is None:
            return None
        return CallbackHandler()

    @contextmanager
    def observation(
        self,
        *,
        name: str,
        as_type: str,
        input_payload: Any | None = None,
        output_payload: Any | None = None,
        metadata: dict[str, Any] | None = None,
        level: str | None = None,
        status_message: str | None = None,
        model: str | None = None,
        model_parameters: dict[str, Any] | None = None,
    ) -> Iterator[Any]:
        if self._client is None:
            with _noop_context() as observation:
                yield observation
            return

        kwargs: dict[str, Any] = {
            "as_type": as_type,
            "name": name,
        }
        if input_payload is not None:
            kwargs["input"] = _sanitize(input_payload)
        if output_payload is not None:
            kwargs["output"] = _sanitize(output_payload)
        if metadata is not None:
            kwargs["metadata"] = _sanitize(metadata)
        if level is not None:
            kwargs["level"] = level
        if status_message is not None:
            kwargs["status_message"] = status_message
        if model is not None:
            kwargs["model"] = model
        if model_parameters is not None:
            kwargs["model_parameters"] = _sanitize(model_parameters)

        with self._client.start_as_current_observation(**kwargs) as observation:
            yield observation

    def _build_client(self) -> Any | None:
        if Langfuse is None:
            return None
        if not self.config.langfuse_enabled:
            return None
        if not self.config.langfuse_public_key or not self.config.langfuse_secret_key:
            return None
        Langfuse(
            public_key=self.config.langfuse_public_key,
            secret_key=self.config.langfuse_secret_key,
            base_url=self.config.langfuse_base_url,
            timeout=self.config.langfuse_timeout_seconds,
            tracing_enabled=True,
        )
        return get_client()
