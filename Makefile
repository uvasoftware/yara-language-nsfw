# yara sources
SOURCEDIR = src
SOURCES =  $(shell cd $(SOURCEDIR) && ls *-language-nsfw.yara)
DESTDIR = ./dist

.PHONY: help build build-yr test test-yr run clean

.DEFAULT_GOAL := help

help: ## Show this help menu
	@echo "Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

build: ## Build the compiled YARA database
	mkdir -p $(DESTDIR)
	yarac src/entrypoint.yara $(DESTDIR)/language-nsfw.db

build-yr: ## Build the compiled YARA-X database
	mkdir -p $(DESTDIR)
	yr compile --include-dir src src/entrypoint.yara -o $(DESTDIR)/language.yr

test: build ## Run suite of tests against compiled YARA database
	@echo "Running detection tests against positive samples..."
	@failed=0; \
	for file in src/test/positive/*.txt; do \
		echo "\n--- Testing $$file ---"; \
		output=$$(yara -C dist/language-nsfw.db "$$file" 2>&1); \
		exit_code=$$?; \
		echo "$$output"; \
		if echo "$$output" | grep -q "^error:"; then \
			echo "ERROR: YARA reported errors"; \
			failed=1; \
		elif [ $$exit_code -ne 0 ]; then \
			echo "ERROR: YARA failed with exit code $$exit_code"; \
			failed=1; \
		fi; \
	done; \
	if [ $$failed -eq 1 ]; then \
		echo "\n--- Tests Failed ---"; \
		exit 1; \
	fi; \

	@echo "Running detection tests against negative samples..."
	@failed=0; \
	for file in src/test/negative/corpus_*.txt; do \
		echo "\n--- Testing $$file ---"; \
		lang=$$(basename "$$file" .txt | sed 's/corpus_//'); \
		rule_file="src/$${lang}-language-nsfw.yara"; \
		if [ ! -f "$$rule_file" ]; then \
			echo "WARNING: Rule file $$rule_file not found, skipping..."; \
			continue; \
		fi; \
		output=$$(yara "$$rule_file" "$$file" 2>&1); \
		exit_code=$$?; \
		if echo "$$output" | grep -q "^error:"; then \
			echo "ERROR: YARA reported errors"; \
			echo "$$output"; \
			failed=1; \
		elif echo "$$output" | grep -qv "^$$"; then \
			echo "ERROR: YARA found a match (false positive)"; \
			echo "$$output"; \
			failed=1; \
		elif [ $$exit_code -ne 0 ]; then \
			echo "ERROR: YARA failed with exit code $$exit_code"; \
			echo "$$output"; \
			failed=1; \
		else \
			echo "PASS: No matches found"; \
		fi; \
	done; \
	if [ $$failed -eq 1 ]; then \
		echo "\n--- Tests Failed ---"; \
		exit 1; \
	fi; \
	echo "\n--- Test Complete ---"

run: build ## Run YARA against source files
	yara src/entrypoint.yara src/

clean: ## Clean up build artifacts
	rm -rf $(DESTDIR)
