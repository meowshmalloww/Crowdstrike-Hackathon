from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "services" / "common"))
from counterflow.evaluation import evaluate_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the deterministic detector against a labeled dataset.")
    parser.add_argument("--dataset", required=True)
    args = parser.parse_args()
    print(json.dumps(evaluate_file(args.dataset), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
