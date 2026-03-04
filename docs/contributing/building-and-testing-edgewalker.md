# Building and Testing EdgeWalker

This guide provides instructions for setting up the development environment, building the project, and running tests for EdgeWalker.

## Prerequisites

EdgeWalker requires the following tools:

- Python 3.13 or higher
- [uv](https://github.com/astral-sh/uv) for dependency management and project execution

## Development Setup

Follow these steps to prepare the local development environment:

1. Clone the repository:
   ```bash
   git clone https://github.com/periphery-security/edgewalker.git
   cd edgewalker
   ```

2. Synchronize dependencies and create a virtual environment:
   ```bash
   uv sync
   ```

## Building the Project

EdgeWalker uses the `hatchling` build backend. To build the project into distributable formats (wheel and sdist), execute:

```bash
uv build
```

The build process places the resulting files in the `dist/` directory.

## Running Tests

EdgeWalker utilizes `pytest` for its test suite.

### Execute All Tests

Run the complete test suite with the following command:

```bash
uv run pytest
```

### Run Tests with Coverage

To generate a coverage report and verify that the code meets the minimum coverage threshold (85%), use the `taskipy` task:

```bash
uv run task test-coverage
```

## Linting and Code Quality

The project maintains high code quality through several tools. Execute these tools individually or via `taskipy` tasks.

### Ruff (Linting and Formatting)

Ruff handles both linting and code formatting.

- Check for linting issues:
  ```bash
  uv run task ruff_lint
  ```
- Automatically fix linting issues:
  ```bash
  uv run task ruff_lint_fix
  ```
- Format the code:
  ```bash
  uv run task ruff_format
  ```

### Static Type Checking

Use `mypy` to verify type hints:

```bash
uv run mypy .
```

### Security Analysis

Run `bandit` to identify common security issues:

```bash
uv run task bandit
```

### Documentation Coverage

Check documentation coverage with `interrogate`:

```bash
uv run task interrogate
```

## Using Pre-commit

EdgeWalker includes a `pre-commit` configuration to automate code quality checks before every commit.

### Install Pre-commit Hooks

After setting up the development environment, install the git hooks:

```bash
uv run pre-commit install
```

### Run Pre-commit Manually

To run all checks against all files in the repository without committing:

```bash
uv run pre-commit run --all-files
```

The hooks automatically run during the `git commit` process. If a hook fails, it blocks the commit until you resolve the issues.
