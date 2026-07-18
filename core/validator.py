from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

from core.config import AppConfig
from core.models import SampleRecord, ValidationResult
from core.ql_policy import QLPolicyResult, validate_ql_policy


class Validator:
    """Deterministic validation entry point for generated rules."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def validate_rule(
        self,
        rule_path: Path,
        *,
        sample: SampleRecord | None = None,
    ) -> ValidationResult:
        policy = validate_ql_policy(rule_path.read_text(encoding="utf-8"))
        if not policy.structure_ok:
            return self._structure_failure(rule_path, policy)

        codeql_executable = self._resolve_codeql_executable()
        if not codeql_executable:
            return self._tool_unavailable(rule_path)

        try:
            self._ensure_query_pack(rule_path)
        except OSError as error:
            return self._environment_failure(
                rule_path,
                notes=[f"Generated query pack could not be prepared: {error}"],
            )

        compile_result = self._validate_with_codeql(rule_path, codeql_executable)
        if compile_result.compile_ok is not True:
            return compile_result
        if self.config.validation_databases_dir is None:
            return compile_result
        return self._validate_mechanism(
            rule_path,
            codeql_executable,
            sample=sample,
            compile_notes=compile_result.notes,
        )

    def _validate_with_codeql(
        self,
        rule_path: Path,
        codeql_executable: str,
    ) -> ValidationResult:
        command = [codeql_executable, "query", "compile", "--check-only"]
        if self.config.codeql_additional_packs:
            additional_packs = os.pathsep.join(
                str(path) for path in self.config.codeql_additional_packs
            )
            command.extend(["--additional-packs", additional_packs])
        command.extend(["--", str(rule_path)])

        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as error:
            return ValidationResult(
                rule_name=rule_path.stem,
                structure_ok=True,
                compile_ok=None,
                recall_ok=None,
                false_positive_ok=None,
                validation_mode="codeql-compile",
                failure_type="tool-execution",
                should_repair=False,
                notes=[f"CodeQL could not be executed: {error}"],
            )

        notes = []
        if completed.stdout.strip():
            notes.append(completed.stdout.strip())
        if completed.stderr.strip():
            notes.append(completed.stderr.strip())

        if completed.returncode != 0 and self._is_environment_error(notes):
            return ValidationResult(
                rule_name=rule_path.stem,
                structure_ok=True,
                compile_ok=None,
                recall_ok=None,
                false_positive_ok=None,
                validation_mode="codeql-compile",
                failure_type="tool-environment",
                should_repair=False,
                notes=notes,
            )

        return ValidationResult(
            rule_name=rule_path.stem,
            structure_ok=True,
            compile_ok=completed.returncode == 0,
            recall_ok=None,
            false_positive_ok=None,
            validation_mode="codeql-compile",
            failure_type="none" if completed.returncode == 0 else "compile-error",
            should_repair=completed.returncode != 0,
            notes=notes or ["CodeQL compile completed without output."],
        )

    def _validate_mechanism(
        self,
        rule_path: Path,
        codeql_executable: str,
        *,
        sample: SampleRecord | None,
        compile_notes: list[str],
    ) -> ValidationResult:
        resolved = self._resolve_validation_databases(rule_path, sample)
        if isinstance(resolved, ValidationResult):
            resolved.notes = [*compile_notes, *resolved.notes]
            return resolved

        cve, vulnerable_database, fixed_database = resolved
        sarif_dir = self.config.results_dir / "sarif"
        try:
            sarif_dir.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            return self._mechanism_tool_failure(
                rule_path,
                cve=cve,
                vulnerable_database=vulnerable_database,
                fixed_database=fixed_database,
                notes=[*compile_notes, f"SARIF output directory could not be prepared: {error}"],
                failure_type="tool-environment",
            )

        vulnerable_sarif = sarif_dir / f"{rule_path.stem}.{cve}.vulnerable.sarif"
        fixed_sarif = sarif_dir / f"{rule_path.stem}.{cve}.fixed.sarif"
        runs = (
            ("vulnerable", vulnerable_database, vulnerable_sarif),
            ("fixed", fixed_database, fixed_sarif),
        )
        analysis_notes = list(compile_notes)

        for variant, database, sarif_path in runs:
            completed, notes = self._run_database_analysis(
                codeql_executable,
                database=database,
                rule_path=rule_path,
                sarif_path=sarif_path,
            )
            analysis_notes.extend(f"{variant}: {note}" for note in notes)
            if completed is None:
                return self._mechanism_tool_failure(
                    rule_path,
                    cve=cve,
                    vulnerable_database=vulnerable_database,
                    fixed_database=fixed_database,
                    vulnerable_sarif=vulnerable_sarif,
                    fixed_sarif=fixed_sarif,
                    notes=analysis_notes,
                    failure_type="tool-execution",
                )
            if completed.returncode != 0:
                failure_type = (
                    "tool-environment"
                    if self._is_environment_error(notes)
                    else "tool-execution"
                )
                return self._mechanism_tool_failure(
                    rule_path,
                    cve=cve,
                    vulnerable_database=vulnerable_database,
                    fixed_database=fixed_database,
                    vulnerable_sarif=vulnerable_sarif,
                    fixed_sarif=fixed_sarif,
                    notes=analysis_notes,
                    failure_type=failure_type,
                )

        try:
            vulnerable_count, vulnerable_locations = self._read_sarif_results(
                vulnerable_sarif
            )
            fixed_count, fixed_locations = self._read_sarif_results(fixed_sarif)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            return self._mechanism_tool_failure(
                rule_path,
                cve=cve,
                vulnerable_database=vulnerable_database,
                fixed_database=fixed_database,
                vulnerable_sarif=vulnerable_sarif,
                fixed_sarif=fixed_sarif,
                notes=[*analysis_notes, f"SARIF results could not be parsed: {error}"],
                failure_type="tool-execution",
            )

        expected_vulnerable = self.config.validation_expected_vulnerable_results
        expected_fixed = self.config.validation_expected_fixed_results
        recall_ok = vulnerable_count == expected_vulnerable
        false_positive_ok = fixed_count == expected_fixed
        if recall_ok and false_positive_ok:
            failure_type = "none"
        elif not recall_ok and not false_positive_ok:
            failure_type = "mechanism-error"
        elif not recall_ok:
            failure_type = "recall-error"
        else:
            failure_type = "false-positive-error"

        analysis_notes.append(
            "Mechanism gate: "
            f"vulnerable expected={expected_vulnerable} actual={vulnerable_count}; "
            f"fixed expected={expected_fixed} actual={fixed_count}."
        )
        return ValidationResult(
            rule_name=rule_path.stem,
            structure_ok=True,
            compile_ok=True,
            recall_ok=recall_ok,
            false_positive_ok=false_positive_ok,
            validation_mode="codeql-mechanism",
            failure_type=failure_type,
            should_repair=not (recall_ok and false_positive_ok),
            notes=analysis_notes,
            vulnerable_result_count=vulnerable_count,
            fixed_result_count=fixed_count,
            expected_vulnerable_result_count=expected_vulnerable,
            expected_fixed_result_count=expected_fixed,
            vulnerable_locations=vulnerable_locations,
            fixed_locations=fixed_locations,
            vulnerable_database=str(vulnerable_database),
            fixed_database=str(fixed_database),
            vulnerable_sarif=str(vulnerable_sarif),
            fixed_sarif=str(fixed_sarif),
        )

    def _resolve_validation_databases(
        self,
        rule_path: Path,
        sample: SampleRecord | None,
    ) -> tuple[str, Path, Path] | ValidationResult:
        if sample is None:
            return self._environment_failure(
                rule_path,
                notes=["Validation databases are configured, but no sample was provided."],
                validation_mode="codeql-mechanism",
                compile_ok=True,
            )

        cve_values = sample.list_field("cve")
        if len(cve_values) != 1:
            return self._environment_failure(
                rule_path,
                notes=[
                    "Mechanism validation requires exactly one CVE to select the "
                    f"database pair; received {len(cve_values)}."
                ],
                validation_mode="codeql-mechanism",
                compile_ok=True,
            )

        cve = cve_values[0].strip()
        database_root = self.config.validation_databases_dir
        if database_root is None:
            raise AssertionError("validation_databases_dir must be configured")
        vulnerable_database = database_root / f"{cve}-vulnerable"
        fixed_database = database_root / f"{cve}-fixed"
        missing = [
            str(path)
            for path in (vulnerable_database, fixed_database)
            if not (path / "codeql-database.yml").is_file()
        ]
        if missing:
            return self._environment_failure(
                rule_path,
                notes=["Validation database metadata not found: " + ", ".join(missing)],
                validation_mode="codeql-mechanism",
                compile_ok=True,
            )
        return cve, vulnerable_database, fixed_database

    def _run_database_analysis(
        self,
        codeql_executable: str,
        *,
        database: Path,
        rule_path: Path,
        sarif_path: Path,
    ) -> tuple[subprocess.CompletedProcess[str] | None, list[str]]:
        command = [
            codeql_executable,
            "database",
            "analyze",
            str(database),
            str(rule_path),
            "--format=sarif-latest",
            f"--output={sarif_path}",
            "--rerun",
        ]
        if self.config.codeql_additional_packs:
            additional_packs = os.pathsep.join(
                str(path) for path in self.config.codeql_additional_packs
            )
            command.extend(["--additional-packs", additional_packs])

        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as error:
            return None, [f"CodeQL analyze could not be executed: {error}"]

        notes = []
        if completed.stdout.strip():
            notes.append(completed.stdout.strip())
        if completed.stderr.strip():
            notes.append(completed.stderr.strip())
        if not notes:
            notes.append("CodeQL analyze completed without output.")
        return completed, notes

    def _read_sarif_results(self, sarif_path: Path) -> tuple[int, list[str]]:
        payload: dict[str, Any] = json.loads(sarif_path.read_text(encoding="utf-8-sig"))
        results = [
            result
            for run in payload.get("runs", [])
            for result in (run.get("results") or [])
        ]
        locations: list[str] = []
        for result in results:
            for location in result.get("locations") or []:
                physical = location.get("physicalLocation") or {}
                artifact = (physical.get("artifactLocation") or {}).get("uri")
                line = (physical.get("region") or {}).get("startLine")
                if artifact and line:
                    rendered = f"{artifact}:{line}"
                elif artifact:
                    rendered = str(artifact)
                else:
                    continue
                if rendered not in locations:
                    locations.append(rendered)
        return len(results), locations

    def _ensure_query_pack(self, rule_path: Path) -> Path:
        pack_path = rule_path.parent / "qlpack.yml"
        if pack_path.is_file():
            return pack_path
        pack_path.write_text(
            "\n".join(
                [
                    "name: freevrg/generated-rules",
                    "version: 0.1.0",
                    "extractor: cpp",
                    "dependencies:",
                    '  codeql/cpp-all: "*"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return pack_path

    def _mechanism_tool_failure(
        self,
        rule_path: Path,
        *,
        cve: str,
        vulnerable_database: Path,
        fixed_database: Path,
        notes: list[str],
        failure_type: str,
        vulnerable_sarif: Path | None = None,
        fixed_sarif: Path | None = None,
    ) -> ValidationResult:
        return ValidationResult(
            rule_name=rule_path.stem,
            structure_ok=True,
            compile_ok=True,
            recall_ok=None,
            false_positive_ok=None,
            validation_mode="codeql-mechanism",
            failure_type=failure_type,  # type: ignore[arg-type]
            should_repair=False,
            notes=notes,
            expected_vulnerable_result_count=(
                self.config.validation_expected_vulnerable_results
            ),
            expected_fixed_result_count=self.config.validation_expected_fixed_results,
            vulnerable_database=str(vulnerable_database),
            fixed_database=str(fixed_database),
            vulnerable_sarif=str(vulnerable_sarif) if vulnerable_sarif else None,
            fixed_sarif=str(fixed_sarif) if fixed_sarif else None,
        )

    def write_result(self, result: ValidationResult) -> Path:
        output_path = self.config.results_dir / f"{result.rule_name}.validation.json"
        output_path.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return output_path

    def _structure_failure(
        self,
        rule_path: Path,
        policy: QLPolicyResult,
    ) -> ValidationResult:
        return ValidationResult(
            rule_name=rule_path.stem,
            structure_ok=False,
            compile_ok=None,
            recall_ok=None,
            false_positive_ok=None,
            validation_mode="static-only",
            failure_type="structure-error",
            should_repair=True,
            notes=[f"QL policy violation: {error}" for error in policy.errors],
        )

    def _environment_failure(
        self,
        rule_path: Path,
        *,
        notes: list[str],
        validation_mode: str = "codeql-compile",
        compile_ok: bool | None = None,
    ) -> ValidationResult:
        return ValidationResult(
            rule_name=rule_path.stem,
            structure_ok=True,
            compile_ok=compile_ok,
            recall_ok=None,
            false_positive_ok=None,
            validation_mode=validation_mode,  # type: ignore[arg-type]
            failure_type="tool-environment",
            should_repair=False,
            notes=notes,
        )

    def _tool_unavailable(self, rule_path: Path) -> ValidationResult:
        return ValidationResult(
            rule_name=rule_path.stem,
            structure_ok=True,
            compile_ok=None,
            recall_ok=None,
            false_positive_ok=None,
            validation_mode="static-only",
            failure_type="tool-unavailable",
            should_repair=False,
            notes=[
                "CodeQL executable not found; structure checks passed but compilation was not run."
            ],
        )

    def _resolve_codeql_executable(self) -> str | None:
        configured = self.config.codeql_path
        if not configured:
            return None
        if Path(configured).is_file():
            return str(Path(configured))
        return shutil.which(configured)

    def _is_environment_error(self, notes: list[str]) -> bool:
        combined = "\n".join(notes).lower()
        exact_environment_signatures = (
            "could not locate a dbscheme",
            "is not inside a qlpack",
            "no valid pack solution found",
            "could not resolve library path for",
        )
        return any(token in combined for token in exact_environment_signatures) or (
            "referenced pack '" in combined and "was not found locally" in combined
        )
