"""Print a short summary of the corpus manifest."""

from __future__ import annotations

from pathlib import Path
import json


MANIFEST_PATH = Path("data/attacks/final/manifest.json")


def main() -> None:
    if not MANIFEST_PATH.exists():
        print(f"[error] Manifest not found at {MANIFEST_PATH}")
        return

    manifest = json.loads(MANIFEST_PATH.read_text())

    print("Manifest summary")
    print("================")
    print(f"version: {manifest.get('version', 'unknown')}")
    print(f"built_at: {manifest.get('built_at', 'unknown')}")
    print(f"sources: {len(manifest.get('sources', []))}")
    print(f"categories: {len(manifest.get('category_counts', {}))}")

    if "category_counts" in manifest:
        print("\nCounts:")
        for category, count in manifest["category_counts"].items():
            print(f"  {category}: {count}")


if __name__ == "__main__":
    main()
