# Agent Guidelines for Edgewalker

This document outlines the essential context and protocols for AI agents contributing to the Edgewalker project.

## Project Overview
Edgewalker functions as a security scanning and periphery infrastructure monitoring tool. It provides a Terminal User Interface (TUI) and CLI for managing various security modules.

## Technical Stack
- **Language:** Python 3.13+
- **Dependency Management:** `uv`
- **TUI Framework:** Textual
- **CLI Framework:** Typer
- **Testing:** `pytest`
- **Linting/Formatting:** `ruff`
- **Static Analysis:** `mypy`, `bandit`

## Core Protocols
Agents must strictly follow these protocols:

### RTFV (Reproduce → Test → Fix → Verify)
1. **Reproduce:** Confirm the issue or requirement through empirical observation or scripts.
2. **Test:** Create a failing test case capturing the desired behavior or bug.
3. **Fix:** Implement the minimal code change necessary to satisfy the test.
4. **Verify:** Run the full test suite to ensure the fix works and introduces no regressions.

### E-Prime Communication
Exclude "to be" verbs (is, am, are, was, were, be, been, being) from all documentation, comments, and user-facing text.

### Pull Request Protocol
Use the GitHub CLI (`gh`) for all Pull Request operations.
- Create a PR: `gh pr create --fill`
- Check PR status: `gh pr status`
- View PR checks: `gh pr checks`
- Merge a PR: `gh pr merge --squash --delete-branch`

## Directory Structure
- `src/edgewalker/core/`: Contains the engine, configuration, and base models.
- `src/edgewalker/modules/`: Houses individual scanning modules (CVE, Port, Password, MAC).
- `src/edgewalker/tui/`: Defines the Textual-based user interface and components.
- `src/edgewalker/cli/`: Defines the Typer-based command line interface.
- `tests/`: Contains the comprehensive test suite.

## Development Commands
- Install dependencies: `uv sync`
- Run tests: `uv run pytest`
- Lint code: `uv run ruff check .`
- Type check: `uv run mypy src`
- Security audit: `uv run bandit -r src/edgewalker`
