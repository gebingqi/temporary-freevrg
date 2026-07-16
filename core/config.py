from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class LLMProfile:
    backend: str
    api_key: str
    base_url: str
    timeout_seconds: int
    model: str
    temperature: float


@dataclass(slots=True)
class AppConfig:
    llm_backend: str
    llm_api_key: str
    llm_base_url: str
    llm_timeout_seconds: int
    pattern_llm_backend: str
    pattern_llm_api_key: str
    pattern_llm_base_url: str
    pattern_llm_timeout_seconds: int
    rule_llm_backend: str
    rule_llm_api_key: str
    rule_llm_base_url: str
    rule_llm_timeout_seconds: int
    pattern_model: str
    rule_model: str
    pattern_temperature: float
    rule_temperature: float
    max_repair_rounds: int
    codeql_path: str
    samples_dir: Path
    patterns_dir: Path
    rules_dir: Path
    results_dir: Path

    def profile_for(self, agent_name: str) -> LLMProfile:
        normalized = agent_name.strip().lower()
        if normalized == "pattern":
            prefix = "PATTERN"
            model = self.pattern_model
            temperature = self.pattern_temperature
        elif normalized == "rule":
            prefix = "RULE"
            model = self.rule_model
            temperature = self.rule_temperature
        else:
            raise ValueError(f"Unsupported agent profile: {agent_name}")
        return LLMProfile(
            backend=getattr(self, f"{prefix.lower()}_llm_backend"),
            api_key=getattr(self, f"{prefix.lower()}_llm_api_key"),
            base_url=getattr(self, f"{prefix.lower()}_llm_base_url"),
            timeout_seconds=getattr(self, f"{prefix.lower()}_llm_timeout_seconds"),
            model=model,
            temperature=temperature,
        )


def read_dotenv(env_path: str = ".env") -> dict[str, str]:
    path = Path(env_path)
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def load_config(env_path: str = ".env") -> AppConfig:
    env_values = read_dotenv(env_path)

    def get(name: str, default: str) -> str:
        return os.getenv(name, env_values.get(name, default))

    return AppConfig(
        llm_backend=get("LLM_BACKEND", "mock"),
        llm_api_key=get("LLM_API_KEY", ""),
        llm_base_url=get("LLM_BASE_URL", ""),
        llm_timeout_seconds=int(get("LLM_TIMEOUT_SECONDS", "60")),
        pattern_llm_backend=get("PATTERN_LLM_BACKEND", get("LLM_BACKEND", "mock")),
        pattern_llm_api_key=get("PATTERN_LLM_API_KEY", get("LLM_API_KEY", "")),
        pattern_llm_base_url=get("PATTERN_LLM_BASE_URL", get("LLM_BASE_URL", "")),
        pattern_llm_timeout_seconds=int(
            get("PATTERN_LLM_TIMEOUT_SECONDS", get("LLM_TIMEOUT_SECONDS", "60"))
        ),
        rule_llm_backend=get("RULE_LLM_BACKEND", get("LLM_BACKEND", "mock")),
        rule_llm_api_key=get("RULE_LLM_API_KEY", get("LLM_API_KEY", "")),
        rule_llm_base_url=get("RULE_LLM_BASE_URL", get("LLM_BASE_URL", "")),
        rule_llm_timeout_seconds=int(
            get("RULE_LLM_TIMEOUT_SECONDS", get("LLM_TIMEOUT_SECONDS", "60"))
        ),
        pattern_model=get("PATTERN_MODEL", "gpt-4.1"),
        rule_model=get("RULE_MODEL", "gpt-4.1"),
        pattern_temperature=float(get("PATTERN_TEMPERATURE", "0.2")),
        rule_temperature=float(get("RULE_TEMPERATURE", "0.1")),
        max_repair_rounds=int(get("MAX_REPAIR_ROUNDS", "2")),
        codeql_path=get("CODEQL_PATH", "codeql"),
        samples_dir=Path(get("SAMPLES_DIR", "data/samples")),
        patterns_dir=Path(get("PATTERNS_DIR", "data/patterns")),
        rules_dir=Path(get("RULES_DIR", "data/rules")),
        results_dir=Path(get("RESULTS_DIR", "data/results")),
    )


def ensure_directories(config: AppConfig) -> None:
    for directory in (
        config.samples_dir,
        config.patterns_dir,
        config.rules_dir,
        config.results_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)
