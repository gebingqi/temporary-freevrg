# Imported Assets

This repository now includes the curated temporary work that had previously lived under `../FreeBSD/`.

The import is organized by role instead of preserving the old ad hoc directory names.

## Directory Map

- `docs/research-notes/`: background notes, system notes, dataset notes, and the Pattern Agent input specification.
- `research/pattern-grounding/`: the revised clustering package, including instance analyses, pattern documents, candidate lists, the grounding script, and the recorded grounding log.
- `research/rule-agent-pilot/`: the first Rule Agent pilot input package, including subtemplates, `rule_input.json` files, working draft queries, and the validation plan.
- `codeql/first-pilot/`: the first candidate CodeQL pack, with queries, metadata, notes, validation documents, the smoke-validation script, and the minimal harness source trees.

## What Was Not Imported

The following generated artifacts were intentionally left out of version control:

- CodeQL databases under `minimal-validation-databases/db/`
- validation logs under `minimal-validation-databases/logs/`
- SARIF outputs under `minimal-validation-databases/results/`

These files are reproducible outputs rather than source inputs. They are now ignored by `.gitignore`.
