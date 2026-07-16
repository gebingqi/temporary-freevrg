from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.config import AppConfig
from core.orchestrator import Orchestrator
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


if __name__ == "__main__":
    unittest.main()
