# Contributing

Thank you for your interest in contributing to Medusa! This guide covers the development workflow, code style, and how to submit changes.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/joshmaster2165/medusa.git
cd medusa

# Install with Poetry
poetry install

# Verify
poetry run medusa --version
poetry run pytest tests/ -v
```

## Running Tests

```bash
# All tests
poetry run pytest tests/ -v

# Specific test file
poetry run pytest tests/unit/test_baseline.py -v

# With coverage
poetry run pytest tests/ --cov=medusa
```

## Code Style

Medusa uses **ruff** for linting and formatting:

```bash
# Check
poetry run ruff check src/ tests/

# Auto-fix
poetry run ruff check --fix src/ tests/

# Format
poetry run ruff format src/ tests/
```

### Style Rules

- Python 3.12+ features are encouraged (StrEnum, `X | Y` union syntax, etc.)
- Line length: 100 characters
- Import sorting: isort-compatible (via ruff)
- Type hints: required for all public functions
- Docstrings: Google or NumPy style

## Type Checking

```bash
poetry run mypy src/medusa/ --ignore-missing-imports
```

## Project Structure

See [Architecture Overview](../architecture/overview.md) for the full module layout.

## Adding a New Check

See [Writing Custom Checks](custom-checks.md) for the complete guide.

**Quick summary:**
1. Create `checks/<category>/<check_id>_name.py`
2. Create `checks/<category>/<check_id>_name.metadata.yaml`
3. Implement `BaseCheck.execute()` → returns `list[Finding]`
4. Add tests in `tests/unit/test_checks/`

## Adding a New Reporter

1. Create `reporters/my_reporter.py`
2. Inherit from `BaseReporter`
3. Implement `generate(result: ScanResult) -> str`
4. Add to the reporter map in `cli/main.py`

## Pull Request Process

1. **Fork** the repo and create a feature branch
2. **Write tests** for your changes
3. **Run the test suite**: `poetry run pytest tests/ -v`
4. **Run lint**: `poetry run ruff check src/ tests/`
5. **Submit a PR** with a clear description

### PR Checklist

- [ ] Tests pass (`pytest tests/ -v`)
- [ ] Lint passes (`ruff check src/ tests/`)
- [ ] New features have tests
- [ ] New checks have metadata YAML files
- [ ] Docstrings for public functions

## Reporting Issues

- Use [GitHub Issues](https://github.com/joshmaster2165/medusa/issues)
- Include: Medusa version, Python version, OS, and steps to reproduce
- For security vulnerabilities, email security@medusa.security

## License

Medusa is licensed under the Apache License 2.0. By contributing, you agree that your contributions will be licensed under the same license.
