# FreeVRG

FreeVRG means `FreeBSD Vulnerability Rule Generator`.

[English](./README.md) | [简体中文](./README.zh-CN.md)

## Overview

This project is a prototype for turning historical FreeBSD vulnerability cases into reusable CodeQL rules.

The current goal is not to build a large platform first. The goal is to make the smallest useful pipeline work:

`sample -> pattern -> rule -> validation`

In this prototype:

- `Pattern Agent` reads structured vulnerability samples and summarizes reusable patterns
- `Rule Agent` turns patterns into CodeQL query prototypes
- `Validator` handles deterministic validation and result recording

## Workflow

```mermaid
flowchart TD
    A[Deterministic: Prepare historical samples] --> B[Deterministic: Split datasets by time]
    B --> C[Deterministic: Use training set for rule generation]
    C --> D[Deterministic: Load .env configuration]
    D --> E[Deterministic: Normalize sample content]
    E --> F[Deterministic: Send to Pattern Agent]
    F --> G[LLM: Extract vulnerability pattern]
    G --> H[Deterministic: Save pattern document]
    H --> I[Deterministic: Send to Rule Agent]
    I --> J[LLM: Generate CodeQL rule]
    J --> K[Deterministic: Save .ql rule]
    K --> L[Deterministic: Validate on validation set]
    L --> M[Deterministic: Write JSON report]
    M --> N[Deterministic: Evaluate on test set or scan current code]
```

Legend:

- `Model-involved`: pattern extraction and rule generation
- `Deterministic / hard-rule`: configuration loading, file IO, sample normalization, validation, and result recording

## Dataset Split

This project uses a time-based dataset split instead of a random split:

- `Training set`: older historical vulnerability samples used for pattern extraction and rule generation
- `Validation set`: mid-period samples used for recall checks, false-positive checks, and rule repair
- `Test set`: newer samples used to evaluate generalization, or to support more realistic scanning after validation passes

This avoids leaking very similar vulnerability patterns into both generation and evaluation. The project is trying to use past vulnerability knowledge to detect later variants, so a time-based split is more credible than a random split.

## Current Status

The repository is currently a prototype skeleton with curated research assets imported.

- directory structure is in place
- `.env`-based configuration is in place
- the main pipeline is wired together
- LLM calls and real CodeQL execution are still placeholders
- pattern-grounding, Rule Agent pilot inputs, and first-pass CodeQL pilot materials are now tracked in-repo

## Project Structure

```text
FreeVRG/
  agents/
  codeql/
  core/
  data/
    samples/
    patterns/
    rules/
    results/
  docs/
  prompts/
  research/
  main.py
  .env.example
  technical_design.md
```

Key directories:

- `agents/`: Pattern Agent and Rule Agent
- `codeql/first-pilot/`: first candidate CodeQL pack, notes, validation plan, and minimal harness sources
- `core/`: config loading, orchestrator, validator
- `data/samples/`: structured historical vulnerability samples
- `data/patterns/`: generated pattern documents
- `data/rules/`: generated CodeQL rules
- `data/results/`: validation results and later scan outputs
- `docs/`: project documentation and imported research notes
- `prompts/`: prompt templates for the two agents
- `research/`: curated pattern-grounding data and Rule Agent pilot inputs

## Imported Research Assets

The temporary work previously stored under `../FreeBSD/` has been reorganized into this repository:

- `research/pattern-grounding/`: revised clustering and grounding package for the training-set CVEs.
  Main contents: `data/instances/` per-CVE analysis notes, `data/patterns/` class-level pattern documents, `_cluster_map.json`, `_rule_candidates.json`, `logs/grounding_train.txt`, and `scripts/grounding_check.py`.
- `research/rule-agent-pilot/`: the first Rule Agent pilot input package built from two `PASS_STRICT` patterns.
  Main contents: per-pattern `rule_input.json`, pattern summaries, subtemplates under `子模板/`, `_class_family_map.json`, the Rule Agent I/O spec, the validation plan, and the working draft `.ql` files under `rules/`.
- `codeql/first-pilot/`: the first candidate CodeQL validation package for the pilot rules.
  Main contents: `queries/` candidate queries, `metadata/` provenance and scope records, `notes/` modeling notes, `validation/` compile and smoke-validation records, `scripts/run_smoke_validation.sh`, and `minimal-validation-databases/source/` with the minimal vulnerable/fixed harness sources for five CVEs.
- `docs/research-notes/`: supporting project notes imported from the temporary workspace.
  Main contents: project background, system architecture notes, dataset notes, and the Pattern Agent input specification.

See `docs/imported-assets.md` for the mapping and the list of intentionally excluded generated artifacts.

## Configuration

Runtime configuration is loaded from `.env`.

Start from:

```bash
cp .env.example .env
```

Important variables:

- `LLM_BACKEND`: `mock` or `openai-compatible`
- `LLM_API_KEY`
- `LLM_BASE_URL`
- `LLM_TIMEOUT_SECONDS`
- `PATTERN_LLM_BACKEND`: optional override for `Pattern Agent`
- `PATTERN_LLM_API_KEY`
- `PATTERN_LLM_BASE_URL`
- `PATTERN_LLM_TIMEOUT_SECONDS`
- `RULE_LLM_BACKEND`: optional override for `Rule Agent`
- `RULE_LLM_API_KEY`
- `RULE_LLM_BASE_URL`
- `RULE_LLM_TIMEOUT_SECONDS`
- `PATTERN_MODEL`
- `RULE_MODEL`
- `PATTERN_TEMPERATURE`
- `RULE_TEMPERATURE`
- `MAX_REPAIR_ROUNDS`
- `CODEQL_PATH`

Configuration behavior:

- Global `LLM_*` values are the default profile for both agents
- `PATTERN_LLM_*` overrides only `Pattern Agent`
- `RULE_LLM_*` overrides only `Rule Agent`
- If `LLM_BACKEND=mock`, the pipeline uses deterministic local fallback generation instead of calling a remote model

## Technology Choices

The current prototype stack is intentionally narrow:

- `PDM`: Python version and dependency management
- `LangGraph`: agent workflow orchestration and state transitions
- `Langfuse`: LLM trace, prompt, latency, and experiment observability
- local `Validator`: deterministic rule compilation and validation

The boundaries are explicit:

- `LangGraph` coordinates the `sample -> pattern -> rule -> validation` flow
- `Langfuse` observes agent execution, but does not replace validation logic
- `Validator` remains the deterministic control layer for compile, recall, and false-positive checks

## Quick Start

1. Copy `.env.example` to `.env`
2. Fill in model and API settings
3. Put a structured sample file into `data/samples/`
4. Run:

```bash
python main.py data/samples/<sample-file>
```

The current pipeline will:

- read the sample
- generate a pattern file
- generate a `.ql` file
- write a placeholder validation result

## Notes

- `technical_design.md` contains the current prototype architecture and workflow design
- generated artifacts under `data/patterns/`, `data/rules/`, and `data/results/` are runtime outputs
- historical samples under `data/samples/` are intended to be curated inputs
- imported research and pilot assets live under `research/`, `codeql/first-pilot/`, and `docs/research-notes/`
