# One-command entry points. On Windows, run from Git Bash (docs/adr/0002).
# CI runs the same tools on Linux. Terraform is plan-only: there is deliberately no apply target.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

TF_ROOTS := $(wildcard infra/terraform/live/*/)

# On Windows, checkov ships as a .cmd launcher rather than an .exe.
CHECKOV := $(if $(filter Windows_NT,$(OS)),uvx --from checkov checkov.cmd,uvx checkov)

.PHONY: help setup lint fmt typecheck test tf-fmt tf-validate tf-lint checkov scan check up down clean

help: ## List targets
	@grep -E '^[a-zA-Z0-9_%-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-12s %s\n", $$1, $$2}'

setup: ## Install Python deps (all workspace packages) and git hooks
	uv sync --all-packages
	uv run pre-commit install

lint: ## Ruff lint + format check
	uv run ruff check .
	uv run ruff format --check .

fmt: ## Auto-format Python and Terraform
	uv run ruff check --fix .
	uv run ruff format .
	terraform fmt -recursive infra/terraform

typecheck: ## mypy (lenient settings in pyproject.toml)
	uv run mypy shared/src

test: ## Run all tests
	uv run pytest

tf-fmt: ## Check Terraform formatting
	terraform fmt -check -recursive infra/terraform

tf-validate: ## terraform init (no backend, no credentials) + validate each root module
	@for d in $(TF_ROOTS); do \
		echo "==> $$d"; \
		terraform -chdir=$$d init -backend=false -input=false -no-color > /dev/null || { echo "init failed in $$d"; exit 1; }; \
		terraform -chdir=$$d validate -no-color; \
	done

tf-lint: ## tflint (skipped locally if not installed; CI always runs it)
	@if command -v tflint > /dev/null; then \
		cd infra/terraform && tflint --init && tflint --recursive --config "$$PWD/.tflint.hcl"; \
	else echo "tflint not installed, skipping (CI runs it)"; fi

checkov: ## Static policy scan of Terraform
	$(CHECKOV) -d infra/terraform --framework terraform --quiet --compact

scan: ## Secret scan of all tracked files (gitleaks via pre-commit)
	uv run pre-commit run gitleaks --all-files

check: lint typecheck test tf-fmt tf-validate ## What CI checks (CI also runs gitleaks, tflint, checkov)

up: ## Start local services (docker-compose.yml arrives with Lab 01)
	@if [ -f docker-compose.yml ]; then docker compose up -d; else echo "No docker-compose.yml yet; it arrives with Lab 01"; fi

down: ## Stop local services and delete their volumes
	@if [ -f docker-compose.yml ]; then docker compose down -v; else echo "Nothing to stop"; fi

lab-%: ## Run one lab, e.g. make lab-01
	@d=$$(ls -d labs/$*-*/ 2> /dev/null | head -1); \
	if [ -n "$$d" ] && [ -f "$$d/Makefile" ]; then $(MAKE) -C "$$d" run; \
	else echo "Lab $* isn't built yet; see PROGRESS.md"; fi

clean: ## Remove caches
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
