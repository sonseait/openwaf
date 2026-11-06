.DEFAULT_GOAL := help

CARGO ?= cargo
ENV_FILE ?=

# Binaries parse dotenv before spawning threads; do not source it in a shell.
define run_with_env
@$(if $(ENV_FILE),OPENWAF_ENV_FILE="$(ENV_FILE)" )$(CARGO) run --locked -p $(1)
endef

.PHONY: help dev run admin collector build release fmt fmt-check clippy test check

help:
	@printf '%s\n' \
	  'OpenWAF backend (run: make -C backend <target>)' \
	  '' \
	  'Native Rust targets (Linux + native dependencies; binaries load .env if present):' \
	  '  dev / run       Run managed or standalone gateway, selected by environment' \
	  '  admin           Run standalone Admin API (no managed proxy/config)' \
	  '  collector       Run read-only discovery collector separately' \
	  '  build           Build workspace debug binaries with locked dependencies' \
	  '  release         Build workspace release binaries with locked dependencies' \
	  '  fmt             Format Rust workspace' \
	  '  fmt-check       Check Rust formatting' \
	  '  clippy          Lint workspace/all targets; deny warnings' \
	  '  test            Run workspace tests' \
	  '  check           Run fmt-check, clippy, then tests' \
	  '' \
	  'Existing environment overrides .env; ENV_FILE=/dev/null skips loading.' \
	  'See README.md for environment and native dependencies.'

dev: run

run:
	$(call run_with_env,openwaf-gateway)

admin:
	$(call run_with_env,openwaf-admin)

collector:
	$(call run_with_env,openwaf-discovery)

build:
	$(CARGO) build --workspace --locked

release:
	$(CARGO) build --workspace --locked --release

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

test:
	$(CARGO) test --workspace --locked

check:
	$(MAKE) fmt-check
	$(MAKE) clippy
	$(MAKE) test
