from __future__ import annotations

import argparse
from pathlib import Path

from core.config import load_config
from core.orchestrator import Orchestrator


def main() -> None:
    parser = argparse.ArgumentParser(
        description="FreeBSD vulnerability rule generation prototype."
    )
    parser.add_argument(
        "sample",
        type=Path,
        help="Path to a structured vulnerability sample file.",
    )
    args = parser.parse_args()

    config = load_config()
    orchestrator = Orchestrator(config)
    outputs = orchestrator.run_for_sample(args.sample)

    for key, value in outputs.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
