"""Theme Manager for EdgeWalker.

Handles discovery and loading of YAML-based skins from bundled and XDG folders.
"""

from __future__ import annotations

# Standard Library
from pathlib import Path
from typing import Any, Dict, List, Optional

# Third Party
import yaml
from platformdirs import user_config_dir
from textual.theme import Theme


class ThemeManager:
    """Manages discovery and loading of EdgeWalker themes."""

    def __init__(self) -> None:
        """Initialize the ThemeManager."""
        self.bundled_dir = Path(__file__).parent.parent / "skins"
        self.user_dir = Path(user_config_dir("edgewalker")) / "themes"
        self._themes: Dict[str, Path] = {}
        self._metadata: Dict[str, Dict[str, Any]] = {}

    def discover_themes(self) -> Dict[str, Path]:
        """Discover all available themes in bundled and user directories.

        Returns:
            Dict mapping theme slug to file path.
        """
        self._themes = {}
        self._metadata = {}

        # 1. Discover bundled themes
        if self.bundled_dir.exists():
            for f in self.bundled_dir.glob("*.yaml"):
                slug = f.stem
                self._themes[slug] = f

        # 2. Discover user themes (XDG)
        if self.user_dir.exists():
            for f in self.user_dir.glob("*.yaml"):
                slug = f.stem
                # User themes override bundled themes with the same slug
                self._themes[slug] = f

        return self._themes

    def get_theme_metadata(self, slug: str) -> Dict[str, Any]:
        """Get metadata for a specific theme.

        Args:
            slug: The theme slug.

        Returns:
            Metadata dictionary.
        """
        if slug in self._metadata:
            return self._metadata[slug]

        path = self._themes.get(slug)
        if not path or not path.exists():
            return {"name": slug, "author": "Unknown"}

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                meta = data.get("metadata", {})
                self._metadata[slug] = {
                    "name": meta.get("name", slug),
                    "author": meta.get("author", "Unknown"),
                }
                return self._metadata[slug]
        except Exception:
            return {"name": slug, "author": "Unknown"}

    def list_themes(self) -> List[Dict[str, Any]]:
        """List all discovered themes with their metadata.

        Returns:
            List of theme info dictionaries.
        """
        self.discover_themes()
        results = []
        for slug in sorted(self._themes.keys()):
            meta = self.get_theme_metadata(slug)
            results.append({
                "slug": slug,
                "name": meta["name"],
                "author": meta["author"],
                "path": self._themes[slug],
            })
        return results

    def load_theme(self, slug: str) -> Dict[str, Any]:
        """Load a theme by slug, falling back to 'periphery' if necessary.

        Args:
            slug: The theme slug to load.

        Returns:
            Dictionary containing theme data (theme, icons, ui).
        """
        self.discover_themes()

        # Always load periphery as base
        default_path = self.bundled_dir / "periphery.yaml"
        base_data = {}
        if default_path.exists():
            try:
                with open(default_path, "r", encoding="utf-8") as f:
                    base_data = yaml.safe_load(f) or {}
            except (OSError, yaml.YAMLError):
                pass  # nosec: B110 - best effort loading of default theme

        if slug == "periphery" or slug == "default" or slug not in self._themes:
            return base_data

        try:
            path = self._themes[slug]
            with open(path, "r", encoding="utf-8") as f:
                theme_data = yaml.safe_load(f) or {}

                # Deep merge theme, icons, and ui
                for section in ["theme", "icons", "ui"]:
                    if section in theme_data and isinstance(theme_data[section], dict):
                        if section not in base_data:
                            base_data[section] = {}
                        base_data[section].update(theme_data[section])

                return base_data
        except Exception:
            return base_data

    def load_textual_theme(self, slug: str) -> Optional[object]:
        """Load a theme by slug and return a Textual Theme object.

        Args:
            slug: The theme slug to load.

        Returns:
            A textual.theme.Theme instance or None.
        """
        data = self.load_theme(slug)
        theme_data = data.get("theme", {})

        # Map slug 'default' to 'periphery'
        theme_name = "periphery" if slug == "default" else slug

        # Extract standard fields for Textual Theme
        standard_fields = [
            "primary",
            "secondary",
            "warning",
            "error",
            "success",
            "accent",
            "foreground",
            "background",
            "surface",
            "panel",
            "boost",
            "dark",
            "luminosity_spread",
            "text_alpha",
        ]

        kwargs = {k: v for k, v in theme_data.items() if k in standard_fields}
        kwargs["variables"] = theme_data.get("variables", {})
        kwargs["name"] = theme_name

        try:
            return Theme(**kwargs)
        except Exception:
            return None


# Global instance
theme_manager = ThemeManager()
