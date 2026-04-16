PYTHON := python
TENANT ?= organizations

.PHONY: test
test:
	$(PYTHON) -m pytest

.PHONY: login
login:
	@if command -v az >/dev/null 2>&1; then \
		BROWSER=firefox az login --tenant "$(TENANT)"; \
	else \
		echo "Azure CLI is required. Install it with: brew install azure-cli"; \
		exit 2; \
	fi

.PHONY: lint
lint:
	$(PYTHON) -m compileall -q src tests

.PHONY: sample
sample:
	$(PYTHON) -m azure_tenant_audit --offline --tenant-name sample --sample examples/sample_audit_bundle/sample_result.json

.PHONY: audit-full
audit-full:
	@./scripts/tenant-audit-full --tenant-id $(TENANT_ID) --tenant-name $(TENANT_NAME)

.PHONY: install
install:
	$(PYTHON) -m pip install -r requirements.txt
