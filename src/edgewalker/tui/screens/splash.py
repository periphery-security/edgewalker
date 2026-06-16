"""EdgeWalker boot splash.

A brief, branded launch screen (logo + tagline + spinner) that auto-dismisses
to reveal the dashboard. It never blocks: any key or click skips it instantly,
per the TUI design guidance that animations must not delay user input.
"""

from __future__ import annotations

# Third Party
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Static

# First Party
from edgewalker import theme

#: Braille spinner frames (modern default per the TUI design system).
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class _SplashLogo(Static):
    """The gradient ASCII logo."""

    def render(self) -> Text:
        """Render the logo with the active theme gradient."""
        return theme.gradient_text(theme.LOGO)


class SplashScreen(Screen):
    """Auto-dismissing branded launch screen."""

    #: Seconds the splash lingers before dissolving to the dashboard.
    DEFAULT_DURATION = 1.2

    def __init__(self, duration: float | None = None) -> None:
        """Initialize the splash.

        Args:
            duration: Seconds to show before auto-dismissing. Defaults to
                :data:`DEFAULT_DURATION`.
        """
        super().__init__()
        self.duration = self.DEFAULT_DURATION if duration is None else duration
        self._frame = 0
        self._done = False

    def compose(self) -> ComposeResult:
        """Compose the centered splash layout."""
        with Vertical(id="splash-container"):
            yield _SplashLogo(id="splash-logo")
            yield Static(theme.TAGLINE, id="splash-tagline")
            yield Static("", id="splash-spinner")

    def on_mount(self) -> None:
        """Start the spinner and schedule auto-dismiss."""
        self.set_interval(0.08, self._tick)
        self.set_timer(self.duration, self._finish)

    def _tick(self) -> None:
        """Advance the spinner frame."""
        self._frame = (self._frame + 1) % len(_SPINNER)
        spinner = self.query_one("#splash-spinner", Static)
        spinner.update(f"[{theme.ACCENT}]{_SPINNER[self._frame]}[/] [{theme.MUTED}]loading…[/]")

    def _finish(self) -> None:
        """Dismiss once (idempotent — timer and key/click may both fire)."""
        if self._done:
            return
        self._done = True
        self.dismiss()

    def on_key(self, event: events.Key) -> None:
        """Skip the splash on any key."""
        self._finish()

    def on_click(self, event: events.Click) -> None:
        """Skip the splash on click."""
        self._finish()
