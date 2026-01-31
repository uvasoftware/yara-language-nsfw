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
	@for file in src/test/*.txt; do \
		echo "\n--- Testing $$file ---"; \
		yara src/entrypoint.yara "$$file" || true; \
	done
	@echo "\n--- Test Complete ---"

test-yr: build-yr
	@echo "Running detection tests with yara-x..."
	@for file in src/test/*.txt; do \
		echo "\n--- Testing $$file ---"; \
		yr scan -C $(DESTDIR)/language.yr "$$file" || true; \
	done
	@echo "\n--- Test Complete ---"

run: build
	yara src/entrypoint.yara src/

clean:
	rm -rf $(DESTDIR)
