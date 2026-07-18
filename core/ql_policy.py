from __future__ import annotations

from dataclasses import dataclass
import re


API_PROFILE_ID = "freevrg-cpp-modular-dataflow-v1"
TESTED_CODEQL_CLI_VERSION = "2.25.6"
TESTED_CPP_ALL_VERSION = "10.2.1-dev"


@dataclass(frozen=True, slots=True)
class QLPolicyResult:
    structure_ok: bool
    errors: tuple[str, ...]


def _uses_variable_target_identity(code: str) -> bool:
    variable_access_names = set(re.findall(r"\bVariableAccess\s+(\w+)\b", code))
    return any(
        re.search(rf"\b{re.escape(name)}\.getTarget\(\)", code)
        for name in variable_access_names
    )


def validate_ql_policy(code: str) -> QLPolicyResult:
    """Check project-level QL structure and the supported C/C++ API profile."""
    errors: list[str] = []

    required_checks = {
        "import statement": re.search(r"(?m)^\s*import\s+\S+", code),
        "@name metadata": re.search(r"(?m)^\s*\*?\s*@name\s+\S+", code),
        "@kind metadata": re.search(r"(?m)^\s*\*?\s*@kind\s+\S+", code),
        "@id metadata": re.search(r"(?m)^\s*\*?\s*@id\s+\S+", code),
        "select clause": re.search(r"(?m)^\s*select\b", code),
    }
    errors.extend(name for name, match in required_checks.items() if match is None)

    if "```" in code:
        errors.append("pure CodeQL without Markdown fences")

    id_match = re.search(r"(?m)^\s*\*?\s*@id\s+(\S+)", code)
    if id_match and not id_match.group(1).startswith("freevrg/"):
        errors.append("@id must use the freevrg/ prefix")

    legacy_import = re.search(
        r"(?m)^\s*import\s+semmle\.code\.cpp\.dataflow\.TaintTracking\b",
        code,
    )
    if legacy_import:
        errors.append("legacy TaintTracking import is not allowed")
    if re.search(
        r"(?m)^\s*class\s+\w+\s+extends\s+TaintTracking::Configuration\b",
        code,
    ):
        errors.append("legacy TaintTracking::Configuration is not allowed")
    if re.search(r"(?m)^\s*import\s+DataFlow::PathGraph\b", code):
        errors.append("DataFlow::PathGraph is not a generated flow-module PathGraph")
    if re.search(r"(?m)^\s*import\s+semmle\.code\.cpp\.controlflow\.Guards\b", code):
        errors.append("the AST-first profile does not use controlflow.Guards")
    if re.search(r"\.getType\(\)\s+instanceof\s+(?:GeOp|GtOp|LeOp|LtOp)\b", code):
        errors.append("comparison operators must use RelationalOperation.getOperator()")
    if re.search(r"\b\w+\.controls\s*\(", code):
        errors.append("the AST-first guard template does not call controls()")

    uses_new_taint_tracking = re.search(
        r"(?m)^\s*import\s+semmle\.code\.cpp\.dataflow\.new\.TaintTracking\b",
        code,
    )
    uses_legacy_flow_sources = re.search(
        r"(?m)^\s*import\s+semmle\.code\.cpp\.security\.FlowSources\b",
        code,
    )
    if uses_new_taint_tracking and uses_legacy_flow_sources:
        errors.append("security.FlowSources must not be mixed with new.TaintTracking")

    if re.search(r"\bAssertion\b", code) and not re.search(
        r"(?m)^\s*import\s+semmle\.code\.cpp\.commons\.Assertions\b",
        code,
    ):
        errors.append("Assertion requires the commons.Assertions import")

    if re.search(r"\.getType\(\)\s+instanceof\s+IntegralType\b", code):
        errors.append(
            "integral type checks must normalize typedefs with getUnspecifiedType"
        )

    uses_guarded_ast_value = (
        re.search(r"\bRelationalOperation\b", code) is not None
        and re.search(r"\b(?:ArrayExpr|PointerDereference)\b", code) is not None
    )
    if uses_guarded_ast_value and not _uses_variable_target_identity(code):
        errors.append(
            "guarded AST queries must use VariableAccess.getTarget for stable identity"
        )

    guard_signatures = re.findall(
        r"(?is)\bpredicate\s+\w*guard\w*\s*\(([^)]*)\)",
        code,
    )
    if any("Expr " in signature and "Variable " not in signature for signature in guard_signatures):
        errors.append(
            "guard predicates must carry Variable identity instead of an Expr occurrence"
        )

    kind_match = re.search(r"(?m)^\s*\*?\s*@kind\s+(\S+)", code)
    kind = kind_match.group(1) if kind_match else None
    uses_modular_dataflow = any(
        pattern.search(code)
        for pattern in (
            re.compile(r"(?m)^\s*module\s+\w+\s+implements\s+DataFlow::ConfigSig\b"),
            re.compile(r"TaintTracking::Global\s*<"),
            re.compile(r"\b\w+::PathNode\b"),
            re.compile(r"\b\w+::flowPath\s*\("),
        )
    )

    if uses_modular_dataflow:
        if not re.search(
            r"(?m)^\s*import\s+semmle\.code\.cpp\.dataflow\.new\.TaintTracking\b",
            code,
        ):
            errors.append("modular dataflow must import new.TaintTracking")
        if not re.search(
            r"(?m)^\s*module\s+\w+\s+implements\s+DataFlow::ConfigSig\b",
            code,
        ):
            errors.append("modular dataflow requires a DataFlow::ConfigSig module")

        flow_modules = set(
            re.findall(
                r"(?m)^\s*module\s+(\w+)\s*=\s*TaintTracking::Global\s*<",
                code,
            )
        )
        path_graph_modules = set(
            re.findall(r"(?m)^\s*import\s+(\w+)::PathGraph\b", code)
        )
        path_node_modules = set(re.findall(r"\b(\w+)::PathNode\b", code))

        if not flow_modules:
            errors.append("modular dataflow requires a TaintTracking::Global flow module")
        if not path_graph_modules:
            errors.append("modular dataflow requires a flow-module PathGraph import")
        if flow_modules and path_graph_modules and not flow_modules.intersection(
            path_graph_modules
        ):
            errors.append("PathGraph import must match the generated flow module")
        if path_node_modules and not path_node_modules.issubset(flow_modules):
            errors.append("PathNode references must use the generated flow module")
        if kind and kind != "path-problem":
            errors.append("modular dataflow queries must use @kind path-problem")
    elif kind and kind != "problem":
        errors.append("AST-first queries must use @kind problem")

    unique_errors = tuple(dict.fromkeys(errors))
    return QLPolicyResult(structure_ok=not unique_errors, errors=unique_errors)
