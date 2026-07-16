from __future__ import annotations

from pathlib import Path

from core.config import AppConfig
from core.llm import LLMGateway, LLMRequest


class BaseAgent:
    def __init__(self, config: AppConfig, prompt_path: Path, agent_name: str) -> None:
        self.config = config
        self.agent_name = agent_name
        self.prompt_path = prompt_path
        self.system_prompt = self._load_prompt(prompt_path)
        self.llm = LLMGateway()
        self.profile = config.profile_for(agent_name)

    def _load_prompt(self, prompt_path: Path) -> str:
        return prompt_path.read_text(encoding="utf-8").strip()

    def invoke_model(self, *, user_prompt: str) -> str | None:
        return self.llm.invoke(
            LLMRequest(
                system_prompt=self.system_prompt,
                user_prompt=user_prompt,
                profile=self.profile,
            )
        )
