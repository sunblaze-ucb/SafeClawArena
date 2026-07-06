#!/usr/bin/env python3
"""
SafeClawArena — Unified Task Generator

Discovers all category modules in contrib/categories/ and generates task JSONs.

Usage:
    python3 contrib/generate.py                              # all categories
    python3 contrib/generate.py --dimension SSI              # one dimension
    python3 contrib/generate.py --category 1.1 3.9           # specific categories
    python3 contrib/generate.py --category 1.7 --dry-run     # preview
    python3 contrib/generate.py --list                        # list available categories
"""

import argparse
import json
import random
import sys
from pathlib import Path

# Add parent dir so `categories` package is importable
sys.path.insert(0, str(Path(__file__).parent))

from categories import GenerationContext, get_registry
from categories._shared import write_task_file


def main():
    parser = argparse.ArgumentParser(
        description="SafeClawArena unified task generator",
    )
    parser.add_argument(
        "--dimension",
        choices=["SSI", "PSE", "CDF"],
        help="Generate tasks for one dimension only",
    )
    parser.add_argument(
        "--category",
        nargs="*",
        help="Generate tasks for specific categories (e.g., 1.1 3.9)",
    )
    parser.add_argument(
        "--output-dir",
        default="tasks/contrib",
        help="Output directory for generated tasks (default: tasks/contrib)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be generated without writing files",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        dest="list_categories",
        help="List all available categories and exit",
    )
    args = parser.parse_args()

    registry = get_registry()

    if not registry:
        print("No category modules found in contrib/categories/.")
        print("Create a .py file with a CATEGORY dict to get started.")
        print("See contrib/categories/example_ssi_1_1.py for reference.")
        return

    # List mode
    if args.list_categories:
        print(f"Available categories ({len(registry)}):\n")
        for key in sorted(registry.keys()):
            cat = registry[key]
            print(f"  {cat['dimension']:4s} {cat['category']:5s}  {cat['category_name']}")
        return

    # Filter
    targets = registry
    if args.dimension:
        targets = {k: v for k, v in targets.items() if v["dimension"] == args.dimension}
    if args.category:
        targets = {k: v for k, v in targets.items() if v["category"] in args.category}

    if not targets:
        print("No matching categories found.")
        if args.category:
            print(f"  Requested: {args.category}")
            print(f"  Available: {[v['category'] for v in registry.values()]}")
        return

    # Generate
    output_dir = Path(args.output_dir)
    random.seed(args.seed)
    ctx = GenerationContext(output_dir=output_dir, seed=args.seed)

    total = 0
    for key in sorted(targets.keys()):
        cat = targets[key]
        print(f"\n{'='*60}")
        print(f"  {cat['dimension']} Cat {cat['category']}: {cat['category_name']}")
        print(f"{'='*60}")

        tasks = cat["generate"](ctx)
        for task in tasks:
            write_task_file(task, output_dir, dry_run=args.dry_run)
        total += len(tasks)
        print(f"  → {len(tasks)} tasks")

    print(f"\n{'='*60}")
    print(f"Total: {total} tasks generated")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
