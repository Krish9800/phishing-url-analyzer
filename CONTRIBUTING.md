# Contributing to Phishing URL Analyzer

We welcome contributions to detection heuristics, homoglyph confusables, and security analysis capabilities.

## Development Workflow

1. Fork and clone the repository.
2. Create and activate a Python 3.12 virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e .[dev]
   ```
3. Implement features test-first (TDD).
4. Run all quality and security gates:
   ```bash
   ruff check .
   ruff format --check .
   mypy src/
   bandit -r src/
   pytest --cov=src --cov-fail-under=90
   ```
5. Submit a pull request.
