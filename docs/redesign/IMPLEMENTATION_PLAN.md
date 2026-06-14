# EdgeWalker — CLI-First Refactor & TUI Redesign: Implementation Plan

> Status: proposal for review. No application code changed yet.
> Companion artifact: [`tui-redesign-mockup.html`](./tui-redesign-mockup.html)
> Decisions locked in: **persistent multi-panel dashboard** as the primary TUI; **CLI-first by contract** (shared in-process engine, *not* subprocessing the CLI binary).

---

## 0. Goals & guardrails

**Goals**

1. Make every capability headless-first and reachable through one canonical entry point, so the CLI and TUI are guaranteed-parity peers ("two products, one package").
2. Remove the logic duplicated between the CLI and TUI (security-warning / override gating).
3. Replace the single-`RichLog` wizard view with a professional persistent multi-panel dashboard.

**Guardrails (apply to every phase)**

- Behaviour-preserving refactors land *before* visual changes. Keep the existing test suite green at each step (`tests/` already covers CLI, controller, scanner service, screens, widgets).
- Conventional commits (`feat:`, `fix:`, `refactor:`, `test:`). Run `pre-commit run --all-files` before concluding each phase.
- No drive-by refactoring outside the touched surface. Tests first where the change is logic-bearing.
- Each phase is independently shippable and independently revertable.

---

## 1. Phase 1 — Extract the use-case ("contract") layer

**Problem today.** `core/scanner_service.py::ScannerService` is already UI-agnostic (returns Pydantic models, emits typed events via `progress_callback`). But the *orchestration policy* lives in two places:
- CLI: `cli/guided.py::GuidedScanner.automatic_mode` sequences port → creds → cve → sql → web.
- TUI: `tui/screens/dashboard.py::_next_guided_step` re-implements the same sequence as a step machine (`_run_guided_port_scan`, `_run_guided_cred_scan`, …), each calling `self.app.scanner` directly.

These two sequencers can drift. The fix is one shared, presentation-free use-case layer.

**New file: `src/edgewalker/core/engine.py`**

```python
@dataclass(frozen=True)
class AssessmentOptions:
    target: str | None = None
    full_scan: bool = False
    full_creds: bool = False
    run_creds: bool = True
    run_cves: bool = True
    run_sql: bool = True
    run_web: bool = True
    unprivileged: bool = False
    top_n: int | None = 10

class Engine:
    """Headless orchestration. No Rich, no Textual, no console I/O."""
    def __init__(self, scanner: ScannerService | None = None): ...

    async def run_port_scan(self, opts, *, on_event=None) -> PortScanModel: ...
    async def run_credential_scan(self, opts, *, on_event=None) -> PasswordScanModel: ...
    async def run_cve_scan(self, opts, *, on_event=None) -> CveScanModel: ...
    async def run_sql_scan(self, opts, *, on_event=None) -> SqlScanModel: ...
    async def run_web_scan(self, opts, *, on_event=None) -> WebScanModel: ...

    # The canonical full sequence, as an async generator of phase results so
    # BOTH front-ends can render incrementally and drive their own step UI.
    async def run_assessment(self, opts, *, on_event=None) -> AsyncIterator[PhaseResult]: ...
```

Notes:
- `on_event` is the existing `progress_callback(event, data)` signature, threaded straight through to `ScannerService`. No new protocol is introduced — this is why we stay in-process rather than subprocessing.
- `run_assessment` yields one `PhaseResult` per module so the TUI can update its sidebar state machine and the CLI can print between phases — replacing both `GuidedScanner.automatic_mode` and the `dashboard._next_guided_step` ladder with consumers of one generator.
- The report-assembly that is currently copy-pasted ~5× in `dashboard.py` (`build_risk_report(...)` after loading every `*_scan.json`) becomes one `Engine.load_report_inputs()` helper returning the dict bundle.

**Edits**
- `cli/guided.py` → `automatic_mode` becomes a thin consumer of `Engine.run_assessment`, keeping only Rich rendering (`utils.print_header`, `display.build_*`).
- `core/scanner_service.py` → unchanged in behaviour; `Engine` composes it. (Keep `ScannerService` as the lower IO/persistence/telemetry layer.)

**Tests**
- New `tests/test_engine.py`: assessment sequencing, option gating (e.g. `run_cves=False` skips CVE), event passthrough, report-input loading. Reuse the `EW_DEMO_MODE` path (`core/demo_service.py`) for deterministic fixtures.
- Existing `test_scanner_service*.py`, `test_cli_guided.py` must stay green.

**Commit:** `refactor(core): add headless Engine use-case layer over ScannerService`

---

## 2. Phase 2 — Single source of truth for the CLI surface & gating

**Problem today.** Security-warning + override gating is duplicated:
- `cli/cli.py::run_guided_scan` (lines ~201–245): builds warnings from `settings.get_security_warnings()` + `get_active_overrides()`, prompts via `typer.confirm`.
- `tui/screens/dashboard.py::_check_security_warnings` (lines ~300–334): rebuilds the same message, prompts via `ConfirmModal`.

**Change**
- Add `core/engine.py::preflight(opts) -> Preflight` returning a structured, render-agnostic object: `{warnings: list[str], overrides: dict[str,str], requires_confirm: bool}`. Pure data — no printing, no prompting.
- CLI renders `Preflight` with Rich + `typer.confirm`; TUI renders it with `ConfirmModal`. The *decision logic* (what triggers a prompt, what `--allow-override` / `silent_mode` / `suppress_warnings` mean) lives once in `preflight`.

**Tests**
- `tests/test_engine.py::test_preflight_*` for the matrix: warnings only, overrides only, both, `allow_override`, `silent_mode`, `suppress_warnings`.
- Keep `test_cli.py` / `test_cli_commands.py` and `test_dashboard_screen*.py` assertions for the rendered behaviour.

**Commit:** `refactor(core): centralize scan preflight gating in Engine`

---

## 3. Phase 3 — TUI redesign: persistent multi-panel dashboard

Target = MOCK 1 in the HTML. Replace the swap-one-`RichLog` model in `dashboard.py` with a real layout that shows grade + network + findings + devices simultaneously, plus a Live-Log view for active scans (MOCK 2).

### 3.1 New widgets (`src/edgewalker/tui/widgets/`)

| File | Widget | Responsibility |
|------|--------|----------------|
| `grade_gauge.py` | `GradeGauge(Static)` | A–F hero + 0–100 bar. Reads `security_report.json` / `RiskEngine`. Colour by grade gradient. |
| `summary_cards.py` | `NetworkCard`, `FindingsCard`, `DeviceTable` | The three overview panels. `DeviceTable` uses Textual `DataTable` with right-aligned risk pills. |
| `navigation.py` (edit) | `NavPanel` | Keep `StatusBadge` (already good). Replace `NavSeparator` ASCII `------` with CSS hairline; regroup into SCAN STATUS / SCAN / VIEW; add cursor highlight for the active view. |

Findings derive from the same `*_scan.json` + `RiskEngine` already used by `build_risk_report`; add a small `core/findings.py::collect_findings(report_inputs) -> list[Finding]` (severity, title, host, detail) so both the card and a future `findings` CLI command share it.

### 3.2 Dashboard screen rework (`tui/screens/dashboard.py`)

- `compose()` → grid: `Header` / `Horizontal(NavPanel, ContentSwitcher)` / context `Footer`. `ContentSwitcher` holds named views: `overview`, `devices`, `findings`, `live-log`.
- Bindings change from numeric to mnemonic, matching the mockup and the `tui-design` lingua franca:
  - `s` quick scan · `S` full scan · `r` re-run all
  - `o` overview · `d` devices · `f` findings · `l` live log
  - `↑↓`/`jk` move · `Enter` drill-in · `Tab` focus · `/` search · `?` help · `q` quit · `esc` cancel/back
  - Keep `1`–`6` as hidden aliases (`show=False`) for one release so existing muscle memory + tests don't break.
- The live-scan flow (`_run_guided_*`) becomes a consumer of `Engine.run_assessment`; it writes to the `live-log` view and updates `NavPanel` badges per `PhaseResult`. The ~150 lines of repeated "open every json, build_risk_report, save" collapse into `Engine.load_report_inputs()`.
- Drop the `blink bold` "Press ENTER" prompt (`_show_continue`); in dashboard mode the assessment auto-advances and the footer shows the cancel/▸ affordance.
- Topology stays (`widgets/topology.py`) as the `devices` view's drill-in (`Enter` on a `DeviceTable` row → device report, matching current `on_tree_node_selected`).

### 3.3 First-run vs returning (per your "wizard then dashboard" instinct, applied lightly)

- Empty state (no `port_scan.json`): `overview` shows a compact call-to-action panel ("Press `s` to run your first scan") instead of empty cards — keeps discoverability without a separate wizard screen.
- `HomeScreen` is retained as the brand landing/telemetry-consent gate, then pushes the dashboard.

**Tests**
- `test_dashboard_screen*.py`, `test_screens_*`, `test_nav_widgets.py`, `test_widgets.py` updated for the new widget tree. Add snapshot-style assertions for `GradeGauge` grade→colour mapping and `DeviceTable` row rendering.
- Use Textual's `App.run_test()` pilot (already used in `test_app_tui.py`) to assert view switching via `o/d/f/l`.

**Commits:** `feat(tui): grade gauge + summary widgets`, `feat(tui): multi-panel dashboard with view switcher`, `feat(tui): drive live scan from Engine.run_assessment`

---

## 4. Phase 4 — Visual system & progressive disclosure

- **`tui/css/edgewalker.tcss`**: introduce semantic design tokens at the top (comment-documented) mapping to the Textual theme vars already wired through `theme_manager` — `$primary` (Electric Violet), `$accent` (Cyan, *accent only*), severity reds/ambers/greens. Replace ad-hoc `$foreground 50%` repetition with a `.muted` class. Add panel/hairline styles for the new widgets.
- **Severity = label + colour everywhere** (mockup legend). Findings carry a text chip so the UI survives `NO_COLOR` and the existing `colorblind` skin (`skins/colorblind.yaml`, Okabe-Ito) stays meaningful.
- **`?` help overlay**: new `tui/modals/help.py::HelpModal` listing the current screen's keymap (Tier 2 of the three-tier help model). Footer stays Tier 1 (only what's actionable now).
- **Contrast fix**: the `periphery` skin's `muted: #555555` on `#0f0f1a` is borderline for WCAG AA; bump muted to ~`#6a6a85` (already used in the mockup) in `skins/periphery.yaml` and verify the other skins.

**Commit:** `feat(tui): semantic css tokens, help overlay, contrast pass`

---

## 5. Phase 5 — Responsiveness & accessibility checklist

Validate against the `tui-design` compatibility checklist:
- [ ] Usable at 80×24: sidebar collapses to icon-only; overview cards stack (Textual constraint layout, no absolute sizes).
- [ ] No crash on resize (`on_resize` reflow; already constraint-based).
- [ ] `NO_COLOR` honoured (severity labels + symbols carry meaning).
- [ ] Works in tmux/zellij and over SSH (no local-only features).
- [ ] Clean exit on `Ctrl+C` restores terminal (Textual handles; verify with the suspend/sudo path in `_handle_permission_error`).
- [ ] `?` overlay reachable from every screen.

**Commit:** `fix(tui): responsive breakpoints + a11y verification`

---

## 6. Optional follow-on — close the CLI parity gap

The TUI exposes a `findings` view that the CLI lacks a direct command for, and `action_view_raw` is a stub ("not yet implemented"). To honour CLI-first parity, add:
- `edgewalker findings` → prints `collect_findings()` (the same data the TUI card shows).
- Wire the TUI `view raw` to the existing `cli/results.py::ResultManager`.

**Commit:** `feat(cli): findings command for TUI/CLI parity`

---

## Sequencing & risk

```
Phase 1 (engine)  ──►  Phase 2 (preflight)  ──►  Phase 3 (dashboard)  ──►  Phase 4 (visual)  ──►  Phase 5 (a11y)
   behaviour-preserving          behaviour-preserving        visible change         polish            verification
```

| Risk | Mitigation |
|------|------------|
| Large `dashboard.py` (998 lines) carries many test hooks (`_write_progress`, `_make_progress_callback`, `_start_guided_flow`). | Keep the backward-compat shims; migrate tests incrementally. Phase 3 is the only risky phase — gate it behind a green Phase 1/2. |
| Numeric keybinding tests (`test_dashboard_screen.py`) assume `[1]`–`[6]`. | Keep numeric aliases hidden for one release. |
| Theme/skin regressions across 7 skins. | Phase 4 contrast pass runs the pilot against each skin slug from `theme_manager.list_themes()`. |

**Net effect:** the CLI and TUI become thin renderers over one `Engine`; the dashboard becomes a real persistent multi-panel UI; and the duplicated sequencing/gating logic collapses to a single source of truth — which is exactly the "CLI-first, two-products-one-package" outcome you were after, achieved by contract rather than by subprocess.
