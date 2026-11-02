# Antigravity POC kit - developer targets (the customer flow is poc/poc-gateway.sh + the endpoint scripts)
.PHONY: help test
help:
	@echo "make test   - unit tests (gateway, hook, credential proxy, kit generator, attack pack, macOS harness)"
test:
	cd gateway && (test -d .venv || python3 -m venv .venv) && .venv/bin/pip install -q -r requirements.txt pytest && .venv/bin/python -m pytest -q -p no:warnings tests
	bash -n install.sh poc/poc-gateway.sh poc/install-macos.sh poc/ci/macos-e2e.sh
