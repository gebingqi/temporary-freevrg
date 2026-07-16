from __future__ import annotations

from dataclasses import dataclass

from core.config import LLMProfile

try:
    from langchain_core.messages import SystemMessage, HumanMessage
    from langchain_openai import ChatOpenAI
except ImportError:  # pragma: no cover - optional runtime dependency
    ChatOpenAI = None
    HumanMessage = None
    SystemMessage = None


@dataclass(slots=True)
class LLMRequest:
    system_prompt: str
    user_prompt: str
    profile: LLMProfile


class LLMGateway:
    def invoke(self, request: LLMRequest) -> str | None:
        backend = request.profile.backend.strip().lower()
        if backend == "mock":
            return None
        if backend == "openai-compatible":
            return self._invoke_openai_compatible(request)
        raise ValueError(
            f"Unsupported LLM_BACKEND={request.profile.backend!r}. "
            "Supported values: mock, openai-compatible."
        )

    def _invoke_openai_compatible(self, request: LLMRequest) -> str:
        if ChatOpenAI is None or SystemMessage is None or HumanMessage is None:
            raise RuntimeError(
                "langchain_openai/langchain_core is not installed, but "
                "LLM_BACKEND=openai-compatible was requested."
            )
        client = ChatOpenAI(
            api_key=request.profile.api_key,
            base_url=request.profile.base_url or None,
            model=request.profile.model,
            temperature=request.profile.temperature,
            timeout=request.profile.timeout_seconds,
        )
        response = client.invoke(
            [
                SystemMessage(content=request.system_prompt),
                HumanMessage(content=request.user_prompt),
            ]
        )
        content = getattr(response, "content", "")
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict) and "text" in item:
                    parts.append(str(item["text"]))
            return "\n".join(parts).strip()
        return str(content).strip()
