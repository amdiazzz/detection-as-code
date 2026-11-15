VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip

.PHONY: help venv install lint fmt test cov scan validate ci clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

venv: ## create the virtualenv (no system pip required)
	python3 -m venv --without-pip $(VENV)
	curl -sS -o $(VENV)/get-pip.py https://bootstrap.pypa.io/get-pip.py
	$(PY) $(VENV)/get-pip.py -q
	rm -f $(VENV)/get-pip.py

install: ## install the package plus dev tooling
	$(PIP) install -q -e ".[dev]"

lint: ## ruff + bandit
	$(VENV)/bin/ruff check src tests
	$(VENV)/bin/ruff format --check src tests
	$(VENV)/bin/bandit -q -c pyproject.toml -r src

fmt: ## autoformat
	$(VENV)/bin/ruff format src tests
	$(VENV)/bin/ruff check --fix src tests

validate: ## schema-validate every rule
	$(PY) -m dac.cli validate

test: ## run the detection test corpus
	$(VENV)/bin/pytest

cov: ## tests with coverage gate
	$(VENV)/bin/pytest --cov --cov-report=term-missing --cov-report=xml

ci: validate lint cov ## everything CI runs

clean:
	rm -rf $(VENV) .pytest_cache .coverage coverage.xml htmlcov dist build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
