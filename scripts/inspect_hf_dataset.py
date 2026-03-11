"""
inspect_hf_dataset.py

Overview
--------
This script helps you inspect Hugging Face datasets before wiring them
into your corpus builder.

What this file does
-------------------
1. Loads one or more Hugging Face datasets.
2. Prints the available splits.
3. Prints column names for each split.
4. Prints a small sample of rows so you can inspect field names.
5. Optionally writes a JSON preview file for deeper inspection.

Why this is useful
------------------
Hugging Face dataset schemas are not always consistent with what you
expect from the dataset card. Before finalizing a normalizer, you should
look at:
- the exact split names
- actual column names
- example row values
- whether important fields are nested, missing, or renamed

Typical workflow
----------------
1. Run this file on a dataset.
2. Look at the columns and sample rows.
3. Patch the corresponding mapper in build_attack_corpus.py.
4. Re-run the corpus builder.

Examples
--------
Inspect one dataset:
    python inspect_hf_dataset.py --dataset neuralchemy/Prompt-injection-dataset

Inspect a specific split:
    python inspect_hf_dataset.py --dataset allenai/wildjailbreak --split train

Inspect multiple datasets:
    python inspect_hf_dataset.py --dataset neuralchemy/Prompt-injection-dataset \
                                 --dataset wambosec/prompt-injections

Write preview JSON files:
    python inspect_hf_dataset.py --dataset gabrielchua/system-prompt-leakage --write-preview

Notes
-----
- Some datasets are gated and require:
      huggingface-cli login
- Some datasets have multiple configurations. If a dataset fails to load,
  try adding a config with --config.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
import argparse
import json
import sys

from datasets import load_dataset, get_dataset_config_names


# Directory where optional preview JSON files are written.
PREVIEW_DIR = Path("data/attacks/previews")
PREVIEW_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# Utility helpers
# ============================================================
# Reusable functions for safe JSON formatting, printing headings,
# and converting dataset rows into preview-friendly structures.
# ============================================================

def safe_json(value: Any, indent: int = 2) -> str:
    """Safely serialize Python objects for readable terminal output."""
    try:
        return json.dumps(value, indent=indent, ensure_ascii=False, default=str)
    except TypeError:
        return str(value)


def print_header(title: str) -> None:
    """Print a visual section header in the terminal."""
    line = "=" * len(title)
    print(f"\n{title}\n{line}")


def take_samples(ds, n: int) -> List[Dict[str, Any]]:
    """
    Take up to n rows from a dataset split and return them as plain dicts.
    """
    sample_count = min(n, len(ds))
    return [dict(ds[i]) for i in range(sample_count)]


def write_preview_file(dataset_name: str, split_name: str, rows: List[Dict[str, Any]]) -> Path:
    """
    Write a preview JSON file so you can inspect sample rows outside the terminal.
    """
    safe_dataset_name = dataset_name.replace("/", "__")
    out_path = PREVIEW_DIR / f"{safe_dataset_name}__{split_name}.json"
    out_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return out_path


# ============================================================
# Inspection functions
# ============================================================
# Functions that:
# - discover configs and splits
# - load the dataset
# - print schema details
# - optionally save previews
# ============================================================

def inspect_dataset(
    dataset_name: str,
    split: Optional[str],
    config: Optional[str],
    sample_rows: int,
    write_preview: bool,
) -> None:
    """
    Inspect one Hugging Face dataset.

    Parameters
    ----------
    dataset_name:
        Hugging Face dataset repo ID
    split:
        Optional split name. If omitted, all available splits are inspected.
    config:
        Optional dataset configuration name
    sample_rows:
        Number of example rows to print/save from each split
    write_preview:
        Whether to write preview JSON files
    """
    print_header(f"Dataset: {dataset_name}")

    # First, try to discover configs. Not all datasets expose them cleanly,
    # so failure here is non-fatal.
    try:
        configs = get_dataset_config_names(dataset_name)
        if configs:
            print("Available configs:")
            for cfg in configs:
                print(f"  - {cfg}")
        else:
            print("Available configs: none explicitly listed")
    except Exception as e:
        print(f"Could not fetch config names: {e}")

    # Load either one split or the dataset dict with all splits.
    try:
        if split:
            ds = load_dataset(dataset_name, name=config, split=split)
            splits = {split: ds}
        else:
            ds_dict = load_dataset(dataset_name, name=config)
            splits = dict(ds_dict)
    except Exception as e:
        print(f"Failed to load dataset: {e}")
        return

    print("\nLoaded splits:")
    for split_name in splits:
        print(f"  - {split_name}")

    for split_name, ds in splits.items():
        print_header(f"{dataset_name} | split={split_name}")

        try:
            row_count = len(ds)
        except Exception:
            row_count = "unknown"

        print(f"Row count: {row_count}")
        print(f"Column names: {list(ds.column_names)}")

        # Print the features schema if available.
        try:
            print("\nFeatures schema:")
            print(safe_json(ds.features))
        except Exception as e:
            print(f"Could not print features schema: {e}")

        # Grab a few sample rows.
        try:
            rows = take_samples(ds, sample_rows)
        except Exception as e:
            print(f"Could not retrieve sample rows: {e}")
            continue

        print(f"\nSample rows (showing up to {sample_rows}):")
        for idx, row in enumerate(rows):
            print(f"\n--- sample[{idx}] ---")
            print(safe_json(row))

        if write_preview:
            try:
                out_path = write_preview_file(dataset_name, split_name, rows)
                print(f"\nWrote preview file: {out_path}")
            except Exception as e:
                print(f"Could not write preview file: {e}")


# ============================================================
# CLI setup
# ============================================================
# Command-line interface so you can inspect one or many datasets
# without editing the script.
# ============================================================

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Inspect Hugging Face datasets before writing normalizers."
    )
    parser.add_argument(
        "--dataset",
        action="append",
        required=True,
        help="Hugging Face dataset name. Repeat this flag to inspect multiple datasets.",
    )
    parser.add_argument(
        "--split",
        default=None,
        help="Optional split to inspect. If omitted, all available splits are inspected.",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Optional dataset config name.",
    )
    parser.add_argument(
        "--sample-rows",
        type=int,
        default=3,
        help="Number of sample rows to print from each split.",
    )
    parser.add_argument(
        "--write-preview",
        action="store_true",
        help="Write preview JSON files under data/attacks/previews/.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for dataset inspection."""
    args = parse_args()

    for dataset_name in args.dataset:
        inspect_dataset(
            dataset_name=dataset_name,
            split=args.split,
            config=args.config,
            sample_rows=args.sample_rows,
            write_preview=args.write_preview,
        )


if __name__ == "__main__":
    main()
    
    
    
    python scripts/inspect_hf_dataset.py \
  --dataset neuralchemy/Prompt-injection-dataset \
  --dataset wambosec/prompt-injections \
  --dataset allenai/wildjailbreak \
  --sample-rows 5 \
  --write-preview
  
  
  python scripts/inspect_hf_dataset.py \
  --dataset gabrielchua/system-prompt-leakage \
  --dataset Antijection/prompt-injection-dataset-v1 \
  --dataset Mindgard/evaded-prompt-injection-and-jailbreak-samples \
  --sample-rows 5 \
  --write-preview