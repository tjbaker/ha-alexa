.PHONY: help install install-dev format lint type-check test test-cov clean

help:
	@echo "Available commands:"
	@echo "  make install       - Install production dependencies"
	@echo "  make install-dev   - Install development dependencies"
	@echo "  make format        - Format code with black and ruff"
	@echo "  make lint          - Run linting checks"
	@echo "  make type-check    - Run mypy type checker"
	@echo "  make test          - Run tests"
	@echo "  make test-cov      - Run tests with coverage report"
	@echo "  make clean         - Remove build artifacts and cache"

install:
	pip install -r requirements.txt

install-dev:
	pip install -e ".[dev]"

format:
	@echo "Running black..."
	black .
	@echo "Running ruff format..."
	ruff format .
	@echo "Running ruff fix..."
	ruff check --fix .

lint:
	@echo "Running ruff..."
	ruff check --unsafe-fixes .
	@echo "Running black check..."
	black --check --diff --color .

type-check:
	@echo "Running mypy..."
	mypy alexa_smart_home_handler.py alexa_oauth_handler.py alexa_authorize_handler.py parameter_store.py

test:
	pytest

test-cov:
	pytest --cov-report=term-missing

clean:
	@echo "Cleaning build artifacts and cache..."
	rm -rf .aws-sam/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf .ruff_cache
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "Clean complete"
