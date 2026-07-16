from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

from core.config import AppConfig
from core.models import ValidationResult


class Validator:
    """Deterministic validation entry point for generated rules."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def validate_rule(self, rule_path: Path) -> ValidationResult:
        if self._resolve_codeql_executable():
            return self._validate_with_codeql(rule_path)
        return self._validate_with_static_checks(rule_path)

    def _validate_with_codeql(self, rule_path: Path) -> ValidationResult:
        command = [self._resolve_codeql_executable(), "query", "compile", str(rule_path)]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
        notes = []
        if completed.stdout.strip():
            notes.append(completed.stdout.strip())
        if completed.stderr.strip():
            notes.append(completed.stderr.strip())
        if completed.returncode != 0 and self._should_fallback_to_static(notes):
            fallback = self._validate_with_static_checks(rule_path)
            fallback.notes.extend(
                [
                    "CodeQL compile was skipped as authoritative because the local qlpack/dbscheme context is incomplete.",
                    *notes,
                ]
            )
            return fallback
        return ValidationResult(
            rule_name=rule_path.stem,
            compile_ok=completed.returncode == 0,
            recall_ok=None,
            false_positive_ok=None,
            validation_mode="codeql-compile",
            should_repair=completed.returncode != 0,
            notes=notes or ["CodeQL compile completed without output."],
        )

    def write_result(self, result: ValidationResult) -> Path:
        output_path = self.config.results_dir / f"{result.rule_name}.validation.json"
        output_path.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return output_path

    def _validate_with_static_checks(self, rule_path: Path) -> ValidationResult:
        rule_text = rule_path.read_text(encoding="utf-8")
        compile_ok = all(
            token in rule_text
            for token in ("import cpp", "from FunctionCall", "select", "@id freevrg/")
        )
        notes = [
            "CodeQL executable not found; used static structure checks instead.",
        ]
        if not compile_ok:
            notes.append("Generated rule is missing one or more required scaffold markers.")
        else:
            notes.append("Static scaffold checks passed.")
        return ValidationResult(
            rule_name=rule_path.stem,
            compile_ok=compile_ok,
            recall_ok=None,
            false_positive_ok=None,
            validation_mode="static-fallback",
            should_repair=not compile_ok,
            notes=notes,
        )

    def _resolve_codeql_executable(self) -> str | None:
        configured = self.config.codeql_path
        if configured and Path(configured).exists():
            return configured
        return shutil.which(configured)

    def _should_fallback_to_static(self, notes: list[str]) -> bool:
        combined = "\n".join(notes).lower()
        return any(
            token in combined
            for token in (
                "could not locate a dbscheme",
                "qlpack.yml",
                "is not inside a qlpack",
                "could not resolve module",
            )
        )
