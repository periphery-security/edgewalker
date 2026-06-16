"""The `?` help overlay — Tier 2 of the three-tier help model.

The footer carries only what is actionable right now (Tier 1); this modal is
the on-demand cheat-sheet of the active screen's full keymap, grouped the same
way as the sidebar (SCAN / VIEW / GENERAL).
"""

from __future__ import annotations

# Third Party
from rich.console import RenderableType
from rich.table import Table
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

# First Party
from edgewalker import theme

#: A keymap is an ordered list of (section title, [(key, description), ...]).
KeymapSection = tuple[str, list[tuple[str, str]]]


class HelpModal(ModalScreen):
    """A dismissible cheat-sheet of the active screen's keybindings."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("question_mark", "dismiss", "Close"),
    ]

    def __init__(
        self,
        sections: list[KeymapSection],
        *,
        title: str = "KEYBINDINGS",
        **kwargs: object,
    ) -> None:
        """Initialize the help overlay.

        Args:
            sections: Ordered keymap groups to render.
            title: The overlay heading.
            **kwargs: Extra arguments forwarded to ``ModalScreen``.
        """
        super().__init__(**kwargs)
        self._sections = sections
        self._title = title

    def compose(self) -> ComposeResult:
        """Compose the help panel."""
        with Vertical(classes="modal-container", id="help-container"):
            yield Static(
                f"[{theme.HEADER}]{self._title}[/]", classes="modal-title", id="help-title"
            )
            yield Static(self._build_keymap(), id="help-body")
            yield Static(f"[{theme.MUTED}]Press ? or esc to close[/]", id="help-hint")
            yield Button("Close", variant="primary", id="help-close")

    def _build_keymap(self) -> RenderableType:
        """Render the grouped keymap as a two-column grid."""
        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", style=f"bold {theme.ACCENT}", no_wrap=True)
        grid.add_column(style=theme.TEXT)
        for index, (section, rows) in enumerate(self._sections):
            if index:
                grid.add_row("", "")
            grid.add_row("", Text(section, style=f"bold {theme.PRIMARY}"))
            for key, description in rows:
                grid.add_row(key, description)
        return grid

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Close on the Close button."""
        if event.button.id == "help-close":
            self.dismiss()

    def action_dismiss(self, result: object = None) -> None:
        """Close the modal (Esc / ? binding)."""
        self.dismiss()

    def on_key(self, event: events.Key) -> None:
        """Close on Enter as well."""
        if event.key == "enter":
            self.dismiss()
