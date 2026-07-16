from __future__ import annotations

from pathlib import Path
from typing import Any

from core.config import AppConfig
from core.llm import LLMGateway, LLMRequest
from core.observability import Observability


class BaseAgent:
    def __init__(
        self,
        config: AppConfig,
        prompt_path: Path,
        agent_name: str,
        observability: Observability | None = None,
    ) -> None:
        self.config = config
        self.agent_name = agent_name
        self.prompt_path = prompt_path
        self.system_prompt = self._load_prompt(prompt_path)
        self.llm = LLMGateway()
        self.profile = config.profile_for(agent_name)
        self.observability = observability or Observability(config)

    def _load_prompt(self, prompt_path: Path) -> str:
        return prompt_path.read_text(encoding="utf-8").strip()

    def invoke_model(self, *, user_prompt: str) -> str | None:
        return self.llm.invoke(
            LLMRequest(
                system_prompt=self.system_prompt,
                user_prompt=user_prompt,
                profile=self.profile,
            ),
            callback_handler=self.observability.callback_handler(),
        )

    def observation(self, *, name: str, as_type: str, input_payload: Any, metadata: dict[str, Any]):
        return self.observability.observation(
            name=name,
            as_type=as_type,
            input_payload=input_payload,
            metadata=metadata,
        )
