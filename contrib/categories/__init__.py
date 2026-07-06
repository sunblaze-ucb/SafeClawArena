"""
SafeClawArena Category Registry — Auto-discovers category modules.

Each category module is a Python file in this package that exports a CATEGORY dict:

    CATEGORY = {
        "dimension": "SSI",           # "SSI" | "PSE" | "CDF"
        "category": "1.7",            # e.g., "1.1", "2.3", "3.7"
        "category_name": "My New Attack",
        "generate": generate,         # callable(ctx: GenerationContext) -> list[dict]
    }

Adding a new category = creating one file here. No other changes needed.
"""

import dataclasses
import importlib
import itertools
import pkgutil
from pathlib import Path
from typing import Iterator


@dataclasses.dataclass
class GenerationContext:
    """Shared context passed to every category's generate() function."""

    output_dir: Path
    seed: int = 42
    _counters: dict = dataclasses.field(default_factory=dict)

    def next_id(self, dimension: str, category: str) -> str:
        """Generate next task ID like 'ssi-1.1-001'."""
        prefix = {"SSI": "ssi", "PSE": "pse", "CDF": "cdf"}[dimension]
        key = f"{prefix}-{category}"
        self._counters.setdefault(key, 0)
        self._counters[key] += 1
        return f"{key}-{self._counters[key]:03d}"


# ── Registry ────────────────────────────────────────────────────────────────

_REGISTRY: dict[str, dict] = {}


def discover():
    """Auto-discover all category modules in this package."""
    pkg_dir = Path(__file__).parent
    for info in pkgutil.iter_modules([str(pkg_dir)]):
        if info.name.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f".{info.name}", package=__name__)
        except Exception as e:
            print(f"  WARNING: Failed to import category module {info.name}: {e}")
            continue
        if hasattr(mod, "CATEGORY"):
            cat = mod.CATEGORY
            key = f"{cat['dimension']}:{cat['category']}"
            _REGISTRY[key] = cat


def get_registry() -> dict[str, dict]:
    """Return {dimension:category -> CATEGORY dict} for all discovered modules."""
    if not _REGISTRY:
        discover()
    return _REGISTRY
