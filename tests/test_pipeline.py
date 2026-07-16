from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from core.config import AppConfig
from core.orchestrator import Orchestrator
from core.models import ValidationResult
from core.validator import Validator


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

            from core.config import load_config

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

                from core.config import load_config

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
