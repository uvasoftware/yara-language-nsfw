# yara sources
SOURCEDIR = src
SOURCES =  $(shell cd $(SOURCEDIR) && ls *-language-nsfw.yara)
DESTDIR = ./dist

build:
	mkdir -p $(DESTDIR)
	yarac src/entrypoint.yara $(DESTDIR)/language-nsfw.db

test: build
	yara -C dist/language-nsfw.db src

run: build
	yara dist/language-nsfw.db src/

clean:
	rm -rf $(DESTDIR)
