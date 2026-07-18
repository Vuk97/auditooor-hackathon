# Makefile for auditooor custom Slither detectors
#
# Targets:
#   make test                              — run detector regression suite
#   make run TARGET=<path>                 — run all custom detectors against a target
#   make run TARGET=<path> DETECTOR=<arg>  — run one detector against a target
#   make baseline TARGET=<path>            — run all detectors + save custom-detectors.log in target
#   make clean                             — remove __pycache__
#
# Requires: slither-analyzer, python3, solc-select (for multiple solc versions)

DETECTORS_DIR := $(shell pwd)
RUNNER        := $(DETECTORS_DIR)/run_custom.py
FIXTURES_DIR  := $(DETECTORS_DIR)/test_fixtures
EXPORT_PATH   := export PATH="$$HOME/.foundry/bin:$$HOME/.local/bin:$$HOME/.cargo/bin:$$PATH"

.PHONY: test run baseline clean help

help:
	@echo "Targets:"
	@echo "  make test                              — regression suite (test_fixtures)"
	@echo "  make run TARGET=<path>                 — all detectors vs target"
	@echo "  make run TARGET=<path> DETECTOR=<arg>  — one detector vs target"
	@echo "  make baseline TARGET=<path>            — run all + save to target/custom-detectors.log"
	@echo "  make clean                             — remove __pycache__"

test: clean
	@$(EXPORT_PATH) && bash $(FIXTURES_DIR)/run_tests.sh

run:
ifndef TARGET
	$(error TARGET is required — usage: make run TARGET=/path/to/project)
endif
	@$(EXPORT_PATH) && python3 $(RUNNER) "$(TARGET)" $(DETECTOR)

baseline:
ifndef TARGET
	$(error TARGET is required — usage: make baseline TARGET=/path/to/project)
endif
	@$(EXPORT_PATH) && python3 $(RUNNER) "$(TARGET)" | tee "$(TARGET)/custom-detectors.log"

clean:
	@find $(DETECTORS_DIR) -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
