# Lab 01 entry points. Run `make up` at the repo root first (starts Keycloak).
SHELL := bash
.DEFAULT_GOAL := help

.PHONY: help run client-credentials token-exchange login test-integration

help: ## List targets
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-20s %s\n", $$1, $$2}'

run: ## Start the Contoso Accounts API on http://127.0.0.1:8001
	uv run uvicorn lab01.main:app --host 127.0.0.1 --port 8001

client-credentials: ## Flow: client credentials (contoso-batch)
	uv run python -m lab01.flows.client_credentials

token-exchange: ## Flow: RFC 8693 token exchange (contoso-gateway)
	uv run python -m lab01.flows.token_exchange

login: ## Flow: auth code + PKCE in your browser, then refresh-token rotation
	uv run python -m lab01.flows.auth_code_pkce

test-integration: ## Integration tests against the running Keycloak
	uv run pytest -m integration tests/integration
