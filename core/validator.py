from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json

from core.config import AppConfig


@dataclass(slots=True)
class ValidationResult:
    rule_name: str
    compile_ok: bool
    recall_ok: bool
    false_positive_ok: bool
    notes: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class Validator:
    """Deterministic validation entry point for generated rules."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def validate_rule(self, rule_path: Path) -> ValidationResult:
        # Placeholder behavior until CodeQL execution is wired in.
        return ValidationResult(
            rule_name=rule_path.stem,
            compile_ok=False,
            recall_ok=False,
            false_positive_ok=False,
            notes=["CodeQL validation is not implemented yet."],
        )

    def write_result(self, result: ValidationResult) -> Path:
        output_path = self.config.results_dir / f"{result.rule_name}.validation.json"
        output_path.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return output_path
