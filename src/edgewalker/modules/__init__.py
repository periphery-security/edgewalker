"""EdgeWalker Modules — Auto-discovering scan module registry.

Each subdirectory under ``edgewalker/modules/`` is an independent scan module.
To add a new module, create a new folder with an ``__init__.py`` that defines
a class inheriting from ``ScanModule``.
"""

from __future__ import annotations

# Standard Library
import importlib
import pkgutil

# Third Party
from loguru import logger


class ScanModule:
    """Base class for all EdgeWalker scan modules."""

    name: str = "Base Module"
    slug: str = "base"
    description: str = ""

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Automatically register subclasses in the global registry."""
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "slug") and cls.slug != "base":
            _registry[cls.slug] = cls

    async def scan(self, **kwargs: object) -> object:
        """Execute the scan asynchronously.  Must be overridden by subclasses."""
        raise NotImplementedError


_registry: dict[str, type[ScanModule]] = {}


def get_modules() -> list[type[ScanModule]]:
    """Return a list of all registered scan module classes."""
    return list(_registry.values())


def get_module(slug: str) -> type[ScanModule] | None:
    """Return a specific module class by its slug."""
    return _registry.get(slug)


def _discover_modules() -> None:
    """Walk the modules directory and import everything to trigger registration."""
    for _, name, ispkg in pkgutil.iter_modules(__path__, __name__ + "."):
        if not ispkg:
            continue
        try:
            importlib.import_module(name)
        except Exception:
            logger.warning("Failed to load module %s", name, exc_info=True)


_discover_modules()
