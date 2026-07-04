from __future__ import annotations

from pathlib import Path

from agents.pattern_agent import PatternAgent
from agents.rule_agent import RuleAgent
from core.config import AppConfig, ensure_directories
from core.validator import Validator


class Orchestrator:
    """Run the minimal sample -> pattern -> rule -> validation pipeline."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.pattern_agent = PatternAgent(config)
        self.rule_agent = RuleAgent(config)
        self.validator = Validator(config)

    def run_for_sample(self, sample_path: Path) -> dict[str, str]:
        ensure_directories(self.config)

        sample_text = sample_path.read_text(encoding="utf-8")
        pattern_text = self.pattern_agent.generate_pattern(sample_text)
        pattern_path = self.config.patterns_dir / f"{sample_path.stem}.md"
        pattern_path.write_text(pattern_text, encoding="utf-8")

        rule_text = self.rule_agent.generate_rule(pattern_text)
        rule_path = self.config.rules_dir / f"{sample_path.stem}.ql"
        rule_path.write_text(rule_text, encoding="utf-8")

        validation = self.validator.validate_rule(rule_path)
        result_path = self.validator.write_result(validation)

        return {
            "sample": str(sample_path),
            "pattern": str(pattern_path),
            "rule": str(rule_path),
            "result": str(result_path),
        }
