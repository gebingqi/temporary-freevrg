from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import re
from typing import Any, Literal


def slugify(value: str) -> str:
    lowered = value.strip().lower()
    normalized = re.sub(r"[^a-z0-9]+", "-", lowered)
    return normalized.strip("-") or "sample"


def compact_text(value: Any, *, default: str = "N/A") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        text = value.strip()
        return text or default
    if isinstance(value, list):
        parts = [compact_text(item, default="") for item in value]
        items = [part for part in parts if part]
        return ", ".join(items) if items else default
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


@dataclass(slots=True)
class SampleRecord:
    sample_id: str
    source_path: Path
    payload: dict[str, Any]

    @classmethod
    def from_path(cls, sample_path: Path) -> "SampleRecord":
        payload = json.loads(sample_path.read_text(encoding="utf-8"))
        sample_id = str(payload.get("id") or sample_path.stem)
        return cls(sample_id=sample_id, source_path=sample_path, payload=payload)

    @property
    def slug(self) -> str:
        return slugify(self.sample_id)

    def list_field(self, name: str) -> list[str]:
        raw_value = self.payload.get(name)
        if raw_value is None:
            return []
        if isinstance(raw_value, list):
            return [str(item) for item in raw_value if str(item).strip()]
        if isinstance(raw_value, str) and raw_value.strip():
            return [raw_value.strip()]
        return []

    def text_field(self, name: str, *, default: str = "") -> str:
        return compact_text(self.payload.get(name), default=default)

    def pattern_name(self) -> str:
        cwe_values = self.list_field("cwe")
        subsystem = self.text_field("subsystem", default="generic")
        if cwe_values:
            return slugify(f"{subsystem}-{cwe_values[0]}")
        return self.slug

    def to_prompt_context(self) -> str:
        return "\n".join(
            [
                f"sample_id: {self.sample_id}",
                f"cve: {compact_text(self.payload.get('cve'))}",
                f"subsystem: {self.text_field('subsystem', default='unknown')}",
                f"cwe: {compact_text(self.payload.get('cwe'))}",
                f"affected_versions: {compact_text(self.payload.get('affected_versions'))}",
                f"files_changed: {compact_text(self.payload.get('files_changed'))}",
                "advisory_text:",
                self.text_field("advisory_text", default="N/A"),
                "diff:",
                self.text_field("diff", default="N/A"),
            ]
        )


@dataclass(slots=True)
class ValidationResult:
    rule_name: str
    compile_ok: bool | None
    recall_ok: bool | None
    false_positive_ok: bool | None
    validation_mode: Literal["codeql-compile", "codeql-mechanism", "static-only"]
    should_repair: bool
    notes: list[str] = field(default_factory=list)
    structure_ok: bool = True
    vulnerable_result_count: int | None = None
    fixed_result_count: int | None = None
    expected_vulnerable_result_count: int | None = None
    expected_fixed_result_count: int | None = None
    vulnerable_locations: list[str] = field(default_factory=list)
    fixed_locations: list[str] = field(default_factory=list)
    vulnerable_database: str | None = None
    fixed_database: str | None = None
    vulnerable_sarif: str | None = None
    fixed_sarif: str | None = None
    failure_type: Literal[
        "none",
        "structure-error",
        "tool-unavailable",
        "tool-environment",
        "tool-execution",
        "compile-error",
        "recall-error",
        "false-positive-error",
        "mechanism-error",
    ] = "none"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


WorkflowState = dict[str, Any]
