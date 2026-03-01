"""Check registry that auto-discovers checks from the checks/ directory."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path

from medusa.core.check import BaseCheck


class CheckRegistry:
    """Discovers and manages all available security checks."""

    def __init__(self) -> None:
        self._checks: dict[str, type[BaseCheck]] = {}

    def discover_checks(self, checks_package: str = "medusa.checks") -> None:
        """Auto-discover all checks from the checks package."""
        package = importlib.import_module(checks_package)
        package_path = Path(package.__file__).parent  # type: ignore[arg-type]

        for category_dir in sorted(package_path.iterdir()):
            if not category_dir.is_dir() or category_dir.name.startswith("_"):
                continue

            category_module = f"{checks_package}.{category_dir.name}"

            for module_info in pkgutil.iter_modules([str(category_dir)]):
                if module_info.name.startswith("_"):
                    continue
                # Skip metadata yaml files (only import .py modules)
                if module_info.name.endswith(".metadata"):
                    continue

                module = importlib.import_module(f"{category_module}.{module_info.name}")

                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseCheck)
                        and attr is not BaseCheck
                        and not inspect.isabstract(attr)
                    ):
                        instance = attr()
                        meta = instance.metadata()
                        self._checks[meta.check_id] = attr

    @property
    def check_count(self) -> int:
        return len(self._checks)

    @property
    def check_ids(self) -> list[str]:
        return sorted(self._checks.keys())

    def get_checks(
        self,
        categories: list[str] | None = None,
        severities: list[str] | None = None,
        check_ids: list[str] | None = None,
        exclude_ids: list[str] | None = None,
    ) -> list[BaseCheck]:
        """Return filtered list of check instances."""
        results: list[BaseCheck] = []

        for check_id, check_cls in sorted(self._checks.items()):
            if exclude_ids and check_id in exclude_ids:
                continue
            if check_ids and check_id not in check_ids:
                continue

            instance = check_cls()
            meta = instance.metadata()

            if categories and meta.category not in categories:
                continue
            if severities and meta.severity.value not in severities:
                continue

            results.append(instance)

        return results

    def get_all_checks(self) -> list[BaseCheck]:
        """Return all registered checks as instances."""
        return [cls() for cls in self._checks.values()]

    def get_check_by_id(self, check_id: str) -> BaseCheck | None:
        """Return a single check by ID, or None."""
        cls = self._checks.get(check_id)
        return cls() if cls else None

    def get_categories(self) -> list[str]:
        """Return all unique check categories."""
        categories: set[str] = set()
        for cls in self._checks.values():
            meta = cls().metadata()
            categories.add(meta.category)
        return sorted(categories)

    def get_severity_counts(self) -> dict[str, int]:
        """Return count of checks per severity level."""
        counts: dict[str, int] = {}
        for cls in self._checks.values():
            meta = cls().metadata()
            sev = meta.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts
