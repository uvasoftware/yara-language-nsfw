# yara sources
SOURCEDIR = src
SOURCES =  $(shell cd $(SOURCEDIR) && ls *-language-nsfw.yara)
DESTDIR = dist

all: deps
	$(foreach source,$(SOURCES),yarac $(SOURCEDIR)/$(source) $(DESTDIR)/$(source).db;)

deps:
	mkdir -p $(DESTDIR)

clean:
	rm -rf $(DESTDIR)

bundle: all
	yarac src/language-nsfw.yara $(DESTDIR)/language-nsfw.db

test: bundle
	yara -c dist/en-language-nsfw.yara.db src
