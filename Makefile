.PHONY: help up down test app-test policy-test lint diagram
help: ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'
up: ## build EVERYTHING end to end and prove it works
	./scripts/up.sh
down: ## delete EVERYTHING this repo created (PURGE=1 also drops the state)
	./scripts/down.sh $(if $(PURGE),--purge,)
test: ## live test suite against the running scanner
	./scripts/test.sh
policy-test: ## Rego unit tests
	opa test policies
app-test: ## Python unit tests (includes real-opa evaluation)
	PYTHONPATH=app .venv/bin/pytest app/tests -q
lint: ## opa fmt/check, ruff, terraform fmt+validate, shellcheck
	test -z "$$(opa fmt -l policies)" && opa check --strict policies
	.venv/bin/ruff check app && .venv/bin/ruff format --check app
	terraform -chdir=terraform fmt -check -recursive && terraform -chdir=terraform validate
	shellcheck -S warning -x scripts/*.sh
diagram: ## regenerate docs/img/architecture.{svg,png}
	python3 docs/diagrams/architecture.py && .venv/bin/python3 docs/diagrams/render.py docs/img/architecture.svg docs/img/architecture.png
