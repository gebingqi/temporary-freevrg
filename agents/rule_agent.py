from __future__ import annotations

from pathlib import Path
import re

from agents.base import BaseAgent
from core.config import AppConfig
from core.models import ValidationResult


class RuleAgent(BaseAgent):
    """Generate CodeQL rules from pattern documents."""

    def __init__(self, config: AppConfig) -> None:
        super().__init__(config, Path("prompts/rule_agent.md"), "rule")

    def generate_rule(
        self,
        pattern_text: str,
        *,
        validation_feedback: ValidationResult | None = None,
        attempt: int = 0,
    ) -> str:
        model_output = self.invoke_model(
            user_prompt=self._build_user_prompt(
                pattern_text,
                validation_feedback=validation_feedback,
                attempt=attempt,
            )
        )
        if model_output:
            return model_output.strip() + "\n"

        pattern_name = self._extract_pattern_name(pattern_text)
        predicate_name = self._to_predicate_name(pattern_name)
        sink_names = self._extract_structured_items(pattern_text, "sink")
        source_names = self._extract_structured_items(pattern_text, "source")
        sanitizer_names = self._extract_structured_items(pattern_text, "sanitizer")
        description = self._extract_description(pattern_text)

        sink_predicate = self._build_name_predicate("isPatternSinkName", sink_names)
        source_predicate = self._build_name_predicate("isPatternSourceHint", source_names)
        sanitizer_predicate = self._build_name_predicate(
            "isPatternSanitizerHint", sanitizer_names
        )
        feedback_block = self._format_feedback(validation_feedback)
        metadata_description = description.replace("*/", "* /")

        return f"""import cpp

/**
 * @name {pattern_name}
 * @description {metadata_description}
 * @kind problem
 * @problem.severity warning
 * @id freevrg/{pattern_name}
 * @tags security experimental external/cwe
 */
private predicate {predicate_name}(Function target) {{
  {sink_predicate}
}}

private predicate isPatternSourceHint(string name) {{
  {source_predicate}
}}

private predicate isPatternSanitizerHint(string name) {{
  {sanitizer_predicate}
}}

from FunctionCall call, Function target
where
  target = call.getTarget() and
  {predicate_name}(target)
select
  call,
  "Potential {pattern_name} candidate sink call. Source hints: " +
    any(string name | isPatternSourceHint(name) | name) +
    ". Sanitizer hints: " +
    any(string name | isPatternSanitizerHint(name) | name)

/*
Prompt context:
{self.system_prompt}

Generation attempt: {attempt}
{feedback_block}
*/
"""

    def _extract_pattern_name(self, pattern_text: str) -> str:
        match = re.search(r"^# Pattern:\s+(.+)$", pattern_text, flags=re.MULTILINE)
        return match.group(1).strip() if match else "generated-pattern"

    def _extract_description(self, pattern_text: str) -> str:
        match = re.search(
            r"## Description\n(.+?)(?:\n## |\Z)", pattern_text, flags=re.DOTALL
        )
        if not match:
            return "Generated CodeQL prototype from a normalized pattern document."
        return " ".join(line.strip() for line in match.group(1).splitlines()).strip()

    def _extract_structured_items(self, pattern_text: str, field_name: str) -> list[str]:
        match = re.search(
            rf"^{field_name}:\n((?:  - .+\n)+)",
            pattern_text,
            flags=re.MULTILINE,
        )
        if not match:
            return []
        items = []
        for line in match.group(1).splitlines():
            item = line.replace("  - ", "", 1).strip()
            if item:
                items.append(item)
        return items

    def _build_name_predicate(self, name: str, items: list[str]) -> str:
        values = self._normalize_candidates(items)
        if not values:
            return 'name = "TODO"'
        return "\n  or ".join(f'name = "{value}"' for value in values)

    def _normalize_candidates(self, items: list[str]) -> list[str]:
        values = []
        for item in items:
            lowered = item.lower()
            for token in re.findall(r"[a-z_][a-z0-9_]{2,}", lowered):
                if token not in values:
                    values.append(token)
        return values[:6]

    def _to_predicate_name(self, pattern_name: str) -> str:
        words = re.findall(r"[a-z0-9]+", pattern_name.lower())
        if not words:
            return "isGeneratedPatternSink"
        return "is" + "".join(word.capitalize() for word in words) + "Sink"

    def _format_feedback(self, feedback: ValidationResult | None) -> str:
        if feedback is None:
            return "Validation feedback: none"
        notes = " | ".join(feedback.notes) if feedback.notes else "none"
        return (
            f"Validation feedback: mode={feedback.validation_mode}, "
            f"compile_ok={feedback.compile_ok}, should_repair={feedback.should_repair}, "
            f"notes={notes}"
        )

    def _build_user_prompt(
        self,
        pattern_text: str,
        *,
        validation_feedback: ValidationResult | None,
        attempt: int,
    ) -> str:
        return "\n".join(
            [
                "Generate a single CodeQL query file for the following pattern.",
                "Requirements:",
                "- Output only CodeQL code.",
                "- Include import statements and query metadata.",
                "- Model source, sink, and sanitizer hints from the pattern.",
                f"- Repair attempt index: {attempt}",
                self._format_feedback(validation_feedback),
                "",
                "Pattern document:",
                pattern_text,
            ]
        )
