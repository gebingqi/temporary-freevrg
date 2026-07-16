from __future__ import annotations

from pathlib import Path
from typing import Any

from agents.pattern_agent import PatternAgent
from agents.rule_agent import RuleAgent
from core.config import AppConfig, ensure_directories
from core.models import SampleRecord, ValidationResult, WorkflowState
from core.validator import Validator

try:
    from langgraph.graph import END, START, StateGraph
except ImportError:  # pragma: no cover - exercised by local fallback runtime
    END = "__end__"
    START = "__start__"
    StateGraph = None


class Orchestrator:
    """Run the sample -> pattern -> rule -> validation workflow as a state graph."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.pattern_agent = PatternAgent(config)
        self.rule_agent = RuleAgent(config)
        self.validator = Validator(config)
        self.graph = self._build_graph()

    def run_for_sample(self, sample_path: Path) -> dict[str, str]:
        ensure_directories(self.config)
        initial_state: WorkflowState = {
            "sample_path": sample_path,
            "repair_round": 0,
            "max_repair_rounds": self.config.max_repair_rounds,
        }
        final_state = self.graph.invoke(initial_state)
        return self._build_outputs(final_state)

    def _build_graph(self) -> Any:
        if StateGraph is None:
            return _FallbackWorkflow(self)

        graph = StateGraph(dict)
        graph.add_node("load_sample", self._load_sample)
        graph.add_node("generate_pattern", self._generate_pattern)
        graph.add_node("generate_rule", self._generate_rule)
        graph.add_node("validate_rule", self._validate_rule)

        graph.add_edge(START, "load_sample")
        graph.add_edge("load_sample", "generate_pattern")
        graph.add_edge("generate_pattern", "generate_rule")
        graph.add_edge("generate_rule", "validate_rule")
        graph.add_conditional_edges(
            "validate_rule",
            self._next_after_validation,
            {
                "repair": "generate_rule",
                "complete": END,
            },
        )
        return graph.compile()

    def _load_sample(self, state: WorkflowState) -> WorkflowState:
        sample_path = Path(state["sample_path"])
        sample = SampleRecord.from_path(sample_path)
        return {
            "sample": sample,
            "artifact_stem": sample.slug,
        }

    def _generate_pattern(self, state: WorkflowState) -> WorkflowState:
        sample: SampleRecord = state["sample"]
        pattern_text = self.pattern_agent.generate_pattern(sample)
        pattern_path = self.config.patterns_dir / f"{state['artifact_stem']}.md"
        pattern_path.write_text(pattern_text, encoding="utf-8")
        return {
            "pattern_text": pattern_text,
            "pattern_path": pattern_path,
        }

    def _generate_rule(self, state: WorkflowState) -> WorkflowState:
        pattern_text = state["pattern_text"]
        validation_feedback: ValidationResult | None = state.get("validation")
        attempt = int(state.get("repair_round", 0))
        rule_text = self.rule_agent.generate_rule(
            pattern_text,
            validation_feedback=validation_feedback,
            attempt=attempt,
        )
        rule_path = self.config.rules_dir / f"{state['artifact_stem']}.ql"
        rule_path.write_text(rule_text, encoding="utf-8")
        return {
            "rule_text": rule_text,
            "rule_path": rule_path,
        }

    def _validate_rule(self, state: WorkflowState) -> WorkflowState:
        rule_path = Path(state["rule_path"])
        validation = self.validator.validate_rule(rule_path)
        result_path = self.validator.write_result(validation)
        repair_round = int(state.get("repair_round", 0))
        if validation.should_repair:
            repair_round += 1
        return {
            "validation": validation,
            "result_path": result_path,
            "repair_round": repair_round,
        }

    def _next_after_validation(self, state: WorkflowState) -> str:
        validation: ValidationResult = state["validation"]
        repair_round = int(state.get("repair_round", 0))
        max_repair_rounds = int(state.get("max_repair_rounds", 0))
        if validation.should_repair and repair_round <= max_repair_rounds:
            return "repair"
        return "complete"

    def _build_outputs(self, state: WorkflowState) -> dict[str, str]:
        sample: SampleRecord = state["sample"]
        return {
            "sample": str(sample.source_path),
            "pattern": str(state["pattern_path"]),
            "rule": str(state["rule_path"]),
            "result": str(state["result_path"]),
        }


class _FallbackWorkflow:
    def __init__(self, orchestrator: Orchestrator) -> None:
        self.orchestrator = orchestrator

    def invoke(self, initial_state: WorkflowState) -> WorkflowState:
        state = dict(initial_state)
        state.update(self.orchestrator._load_sample(state))
        state.update(self.orchestrator._generate_pattern(state))
        state.update(self.orchestrator._generate_rule(state))

        while True:
            state.update(self.orchestrator._validate_rule(state))
            if self.orchestrator._next_after_validation(state) != "repair":
                return state
            state.update(self.orchestrator._generate_rule(state))
