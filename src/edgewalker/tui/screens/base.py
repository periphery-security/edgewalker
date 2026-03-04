"""EdgeWalker TUI base screen."""

from __future__ import annotations

# Third Party
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static

# First Party
from edgewalker import theme


class BaseScreen(Screen):
    """Base screen with shared header and footer."""

    def compose(self) -> ComposeResult:
        """Compose the screen layout with header and footer."""
        yield Static("EDGEWALKER", id="header-title")
        yield from self.compose_content()
        yield Static(self.get_footer_text(), id="app-footer")

    def compose_content(self) -> ComposeResult:
        """Override this method to yield screen-specific content."""
        yield from []

    def get_footer_text(self) -> str:
        """Override this method to provide screen-specific footer text."""
        return (
            f"[{theme.MUTED}]q Quit {theme.ICON_DOT} "
            f"Tab/{theme.ICON_UP}{theme.ICON_DOWN} Navigate[/{theme.MUTED}]"
        )

    def update_footer(self, text: str) -> None:
        """Update the footer text dynamically."""
        self.query_one("#app-footer", Static).update(text)
