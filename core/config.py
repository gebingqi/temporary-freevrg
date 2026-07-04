from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class AppConfig:
    llm_api_key: str
    llm_base_url: str
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


def load_dotenv(env_path: str = ".env") -> None:
    path = Path(env_path)
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def load_config() -> AppConfig:
    load_dotenv()

    return AppConfig(
        llm_api_key=os.getenv("LLM_API_KEY", ""),
        llm_base_url=os.getenv("LLM_BASE_URL", ""),
        pattern_model=os.getenv("PATTERN_MODEL", "gpt-4.1"),
        rule_model=os.getenv("RULE_MODEL", "gpt-4.1"),
        pattern_temperature=float(os.getenv("PATTERN_TEMPERATURE", "0.2")),
        rule_temperature=float(os.getenv("RULE_TEMPERATURE", "0.1")),
        max_repair_rounds=int(os.getenv("MAX_REPAIR_ROUNDS", "2")),
        codeql_path=os.getenv("CODEQL_PATH", "codeql"),
        samples_dir=Path(os.getenv("SAMPLES_DIR", "data/samples")),
        patterns_dir=Path(os.getenv("PATTERNS_DIR", "data/patterns")),
        rules_dir=Path(os.getenv("RULES_DIR", "data/rules")),
        results_dir=Path(os.getenv("RESULTS_DIR", "data/results")),
    )


def ensure_directories(config: AppConfig) -> None:
    for directory in (
        config.samples_dir,
        config.patterns_dir,
        config.rules_dir,
        config.results_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)
