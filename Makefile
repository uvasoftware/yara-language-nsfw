# yara sources
SOURCEDIR = src
SOURCES =  $(shell cd $(SOURCEDIR) && ls *-language-nsfw.yara)
DESTDIR = ./dist

build:
	mkdir -p $(DESTDIR)
	yarac src/entrypoint.yara $(DESTDIR)/language-nsfw.db

build-yr:
	mkdir -p $(DESTDIR)
	yr compile --include-dir src src/entrypoint.yara -o $(DESTDIR)/language.yr

test: build
	@echo "Running detection tests..."
	@failed=0; \
	for file in src/test/*.txt; do \
		echo "\n--- Testing $$file ---"; \
		output=$$(yara src/entrypoint.yara "$$file" 2>&1); \
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
	echo "\n--- Test Complete ---"

test-yr: build-yr
	@echo "Running detection tests with yara-x..."
	@failed=0; \
	for file in src/test/*.txt; do \
		echo "\n--- Testing $$file ---"; \
		output=$$(yr scan -C $(DESTDIR)/language.yr "$$file" 2>&1); \
		exit_code=$$?; \
		echo "$$output"; \
		if echo "$$output" | grep -qiE "^error(\[|:)"; then \
			echo "ERROR: yara-x reported errors"; \
			failed=1; \
		elif [ $$exit_code -ne 0 ]; then \
			echo "ERROR: yara-x failed with exit code $$exit_code"; \
			failed=1; \
		fi; \
	done; \
	if [ $$failed -eq 1 ]; then \
		echo "\n--- Tests Failed ---"; \
		exit 1; \
	fi; \
	echo "\n--- Test Complete ---"

run: build
	yara src/entrypoint.yara src/

clean:
	rm -rf $(DESTDIR)
