from __future__ import annotations

from contextlib import contextmanager
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.config import AppConfig, load_config
from core.orchestrator import Orchestrator
from core.models import ValidationResult
from core.validator import Validator


def _make_config(root: Path, **overrides: object) -> AppConfig:
    values = {
        "langfuse_enabled": False,
        "langfuse_public_key": "",
        "langfuse_secret_key": "",
        "langfuse_base_url": "https://cloud.langfuse.com",
        "langfuse_timeout_seconds": 5,
        "llm_backend": "mock",
        "llm_api_key": "",
        "llm_base_url": "",
        "llm_timeout_seconds": 60,
        "pattern_llm_backend": "mock",
        "pattern_llm_api_key": "",
        "pattern_llm_base_url": "",
        "pattern_llm_timeout_seconds": 60,
        "rule_llm_backend": "mock",
        "rule_llm_api_key": "",
        "rule_llm_base_url": "",
        "rule_llm_timeout_seconds": 60,
        "pattern_model": "test-pattern",
        "rule_model": "test-rule",
        "pattern_temperature": 0.0,
        "rule_temperature": 0.0,
        "max_repair_rounds": 1,
        "codeql_path": "missing-codeql-executable",
        "samples_dir": root / "samples",
        "patterns_dir": root / "patterns",
        "rules_dir": root / "rules",
        "results_dir": root / "results",
    }
    values.update(overrides)
    return AppConfig(**values)


def _write_sample(root: Path, sample_id: str) -> Path:
    sample_path = root / "sample.json"
    sample_path.write_text(
        json.dumps(
            {
                "id": sample_id,
                "cve": ["CVE-2020-7461"],
                "subsystem": "net",
                "advisory_text": "Observation ordering test sample.",
            }
        ),
        encoding="utf-8",
    )
    return sample_path


class _RecordingObservation:
    def update(self, **_: object) -> None:
        return None


class _RecordingObservability:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    @contextmanager
    def observation(self, *, name: str, **_: object):
        self.events.append(f"enter:{name}")
        try:
            yield _RecordingObservation()
        finally:
            self.events.append(f"exit:{name}")

    def flush(self) -> None:
        self.events.append("flush")


class _FailingGraph:
    def invoke(self, _: object) -> None:
        raise RuntimeError("graph failed")


class PipelineTests(unittest.TestCase):
    def test_orchestrator_generates_pattern_rule_and_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_path = root / "sample.json"
            sample_path.write_text(
                json.dumps(
                    {
                        "id": "FreeBSD-SA-TEST",
                        "cve": ["CVE-2020-7461"],
                        "cwe": ["CWE-125"],
                        "subsystem": "net",
                        "files_changed": ["sys/net/foo.c"],
                        "advisory_text": "Network packet length is used without minimum validation.",
                        "diff": "if (pkt_len < 4) return EINVAL;",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            config = AppConfig(
                langfuse_enabled=False,
                langfuse_public_key="",
                langfuse_secret_key="",
                langfuse_base_url="https://cloud.langfuse.com",
                langfuse_timeout_seconds=5,
                llm_backend="mock",
                llm_api_key="",
                llm_base_url="",
                llm_timeout_seconds=60,
                pattern_llm_backend="mock",
                pattern_llm_api_key="",
                pattern_llm_base_url="",
                pattern_llm_timeout_seconds=60,
                rule_llm_backend="mock",
                rule_llm_api_key="",
                rule_llm_base_url="",
                rule_llm_timeout_seconds=60,
                pattern_model="test-pattern",
                rule_model="test-rule",
                pattern_temperature=0.0,
                rule_temperature=0.0,
                max_repair_rounds=1,
                codeql_path="codeql",
                samples_dir=root / "samples",
                patterns_dir=root / "patterns",
                rules_dir=root / "rules",
                results_dir=root / "results",
            )

            outputs = Orchestrator(config).run_for_sample(sample_path)

            pattern_path = Path(outputs["pattern"])
            rule_path = Path(outputs["rule"])
            result_path = Path(outputs["result"])

            self.assertTrue(pattern_path.exists())
            self.assertTrue(rule_path.exists())
            self.assertTrue(result_path.exists())
            self.assertIn("# Pattern:", pattern_path.read_text(encoding="utf-8"))
            self.assertIn("@id freevrg/", rule_path.read_text(encoding="utf-8"))

            result_data = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertTrue(result_data["compile_ok"])
            self.assertEqual(result_data["validation_mode"], "static-fallback")

    def test_validator_static_fallback_marks_missing_scaffold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rule_path = root / "broken.ql"
            rule_path.write_text("import cpp\nfrom Function f\nselect f\n", encoding="utf-8")
            config = AppConfig(
                langfuse_enabled=False,
                langfuse_public_key="",
                langfuse_secret_key="",
                langfuse_base_url="https://cloud.langfuse.com",
                langfuse_timeout_seconds=5,
                llm_backend="mock",
                llm_api_key="",
                llm_base_url="",
                llm_timeout_seconds=60,
                pattern_llm_backend="mock",
                pattern_llm_api_key="",
                pattern_llm_base_url="",
                pattern_llm_timeout_seconds=60,
                rule_llm_backend="mock",
                rule_llm_api_key="",
                rule_llm_base_url="",
                rule_llm_timeout_seconds=60,
                pattern_model="test-pattern",
                rule_model="test-rule",
                pattern_temperature=0.0,
                rule_temperature=0.0,
                max_repair_rounds=1,
                codeql_path="codeql",
                samples_dir=root / "samples",
                patterns_dir=root / "patterns",
                rules_dir=root / "rules",
                results_dir=root / "results",
            )

            result = Validator(config).validate_rule(rule_path)

            self.assertFalse(result.compile_ok)
            self.assertTrue(result.should_repair)

    def test_load_config_reads_llm_backend_from_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            env_path = root / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "LLM_BACKEND=openai-compatible",
                        "LANGFUSE_ENABLED=true",
                        "LANGFUSE_PUBLIC_KEY=pk-lf-test",
                        "LANGFUSE_SECRET_KEY=sk-lf-test",
                        "LANGFUSE_BASE_URL=\"https://langfuse.example.com\"",
                        "LANGFUSE_TIMEOUT_SECONDS=7",
                        "LLM_API_KEY=test-key",
                        "LLM_BASE_URL=https://example.invalid/v1",
                        "LLM_TIMEOUT_SECONDS=42",
                        "PATTERN_LLM_BASE_URL=https://pattern.invalid/v1",
                        "RULE_LLM_API_KEY=rule-key",
                        "RULE_LLM_TIMEOUT_SECONDS=33",
                        "PATTERN_MODEL=model-a",
                        "RULE_MODEL=model-b",
                    ]
                ),
                encoding="utf-8",
            )

            config = load_config(str(env_path))

            self.assertTrue(config.langfuse_enabled)
            self.assertEqual(config.langfuse_public_key, "pk-lf-test")
            self.assertEqual(config.langfuse_secret_key, "sk-lf-test")
            self.assertEqual(config.langfuse_base_url, "https://langfuse.example.com")
            self.assertEqual(config.langfuse_timeout_seconds, 7)
            self.assertEqual(config.llm_backend, "openai-compatible")
            self.assertEqual(config.llm_api_key, "test-key")
            self.assertEqual(config.llm_base_url, "https://example.invalid/v1")
            self.assertEqual(config.llm_timeout_seconds, 42)
            self.assertEqual(config.pattern_llm_base_url, "https://pattern.invalid/v1")
            self.assertEqual(config.pattern_llm_api_key, "test-key")
            self.assertEqual(config.rule_llm_api_key, "rule-key")
            self.assertEqual(config.rule_llm_timeout_seconds, 33)
            self.assertEqual(config.pattern_model, "model-a")
            self.assertEqual(config.rule_model, "model-b")

    def test_load_config_applies_proxy_environment_from_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            env_path = root / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "HTTP_PROXY=http://127.0.0.1:7897",
                        "HTTPS_PROXY=http://127.0.0.1:7897",
                        "ALL_PROXY=http://127.0.0.1:7897",
                        "NO_PROXY=127.0.0.1,localhost",
                    ]
                ),
                encoding="utf-8",
            )

            original = {key: os.environ.get(key) for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")}
            try:
                for key in original:
                    os.environ.pop(key, None)

                load_config(str(env_path))

                self.assertEqual(os.environ.get("HTTP_PROXY"), "http://127.0.0.1:7897")
                self.assertEqual(os.environ.get("HTTPS_PROXY"), "http://127.0.0.1:7897")
                self.assertEqual(os.environ.get("ALL_PROXY"), "http://127.0.0.1:7897")
                self.assertEqual(os.environ.get("NO_PROXY"), "127.0.0.1,localhost")
            finally:
                for key, value in original.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

    def test_load_config_treats_blank_agent_overrides_as_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            env_path = Path(tmp_dir) / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "LLM_BACKEND=openai-compatible",
                        "LLM_API_KEY=shared-key",
                        "LLM_BASE_URL=https://shared.invalid/v1",
                        "LLM_TIMEOUT_SECONDS=60",
                        "PATTERN_LLM_BACKEND=",
                        "PATTERN_LLM_API_KEY=",
                        "PATTERN_LLM_BASE_URL=   ",
                        "PATTERN_LLM_TIMEOUT_SECONDS=",
                        "RULE_LLM_BACKEND=",
                        "RULE_LLM_API_KEY=",
                        "RULE_LLM_BASE_URL=",
                        "RULE_LLM_TIMEOUT_SECONDS=   ",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"LLM_BACKEND": " "}, clear=True):
                config = load_config(str(env_path))

            self.assertEqual(config.pattern_llm_backend, "openai-compatible")
            self.assertEqual(config.pattern_llm_api_key, "shared-key")
            self.assertEqual(config.pattern_llm_base_url, "https://shared.invalid/v1")
            self.assertEqual(config.pattern_llm_timeout_seconds, 60)
            self.assertEqual(config.rule_llm_backend, "openai-compatible")
            self.assertEqual(config.rule_llm_api_key, "shared-key")
            self.assertEqual(config.rule_llm_base_url, "https://shared.invalid/v1")
            self.assertEqual(config.rule_llm_timeout_seconds, 60)

    def test_validator_does_not_treat_codeql_directory_as_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            codeql_dir = root / "codeql"
            codeql_dir.mkdir()
            rule_path = root / "valid.ql"
            rule_path.write_text(
                "import cpp\n/** @id freevrg/test */\nfrom FunctionCall call\nselect call\n",
                encoding="utf-8",
            )
            config = _make_config(root, codeql_path=str(codeql_dir))

            with (
                patch("core.validator.shutil.which", return_value=None) as which_mock,
                patch("core.validator.subprocess.run") as run_mock,
            ):
                result = Validator(config).validate_rule(rule_path)

            self.assertTrue(result.compile_ok)
            self.assertEqual(result.validation_mode, "static-fallback")
            which_mock.assert_called_once_with(str(codeql_dir))
            run_mock.assert_not_called()

    def test_orchestrator_closes_root_observation_before_flush(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_path = _write_sample(root, "FreeBSD-SA-OBSERVABILITY")
            orchestrator = Orchestrator(_make_config(root))
            events: list[str] = []
            orchestrator.observability = _RecordingObservability(events)

            outputs = orchestrator.run_for_sample(sample_path)

            self.assertTrue(Path(outputs["result"]).exists())
            self.assertEqual(events[-2:], ["exit:run-sample-pipeline", "flush"])

    def test_orchestrator_closes_root_observation_before_flush_on_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_path = _write_sample(root, "FreeBSD-SA-OBSERVABILITY-ERROR")
            orchestrator = Orchestrator(_make_config(root))
            orchestrator.graph = _FailingGraph()
            events: list[str] = []
            orchestrator.observability = _RecordingObservability(events)

            with self.assertRaisesRegex(RuntimeError, "graph failed"):
                orchestrator.run_for_sample(sample_path)

            self.assertEqual(
                events,
                ["enter:run-sample-pipeline", "exit:run-sample-pipeline", "flush"],
            )

    def test_orchestrator_repair_path_preserves_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_path = root / "sample.json"
            sample_path.write_text(
                json.dumps(
                    {
                        "id": "FreeBSD-SA-REPAIR",
                        "cve": ["CVE-2020-7461"],
                        "subsystem": "net",
                        "advisory_text": "Repair path coverage sample.",
                    }
                ),
                encoding="utf-8",
            )
            config = AppConfig(
                langfuse_enabled=False,
                langfuse_public_key="",
                langfuse_secret_key="",
                langfuse_base_url="https://cloud.langfuse.com",
                langfuse_timeout_seconds=5,
                llm_backend="mock",
                llm_api_key="",
                llm_base_url="",
                llm_timeout_seconds=60,
                pattern_llm_backend="mock",
                pattern_llm_api_key="",
                pattern_llm_base_url="",
                pattern_llm_timeout_seconds=60,
                rule_llm_backend="mock",
                rule_llm_api_key="",
                rule_llm_base_url="",
                rule_llm_timeout_seconds=60,
                pattern_model="test-pattern",
                rule_model="test-rule",
                pattern_temperature=0.0,
                rule_temperature=0.0,
                max_repair_rounds=1,
                codeql_path="codeql",
                samples_dir=root / "samples",
                patterns_dir=root / "patterns",
                rules_dir=root / "rules",
                results_dir=root / "results",
            )
            orchestrator = Orchestrator(config)
            calls = {"count": 0}

            def fake_validate_rule(rule_path: Path) -> ValidationResult:
                calls["count"] += 1
                if calls["count"] == 1:
                    return ValidationResult(
                        rule_name=rule_path.stem,
                        compile_ok=False,
                        recall_ok=None,
                        false_positive_ok=None,
                        validation_mode="static-fallback",
                        should_repair=True,
                        notes=["first pass fails"],
                    )
                return ValidationResult(
                    rule_name=rule_path.stem,
                    compile_ok=True,
                    recall_ok=None,
                    false_positive_ok=None,
                    validation_mode="static-fallback",
                    should_repair=False,
                    notes=["second pass succeeds"],
                )

            orchestrator.validator.validate_rule = fake_validate_rule
            outputs = orchestrator.run_for_sample(sample_path)

            self.assertEqual(calls["count"], 2)
            self.assertTrue(Path(outputs["rule"]).exists())
            self.assertTrue(Path(outputs["result"]).exists())


if __name__ == "__main__":
    unittest.main()
