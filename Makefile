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

# extracts string content from a text file into yara-like format
# also removes any words in our general whitelist
extract:
	cat $(filter-out $@,$(MAKECMDGOALS)) | sort | uniq -u | grep -v -x -f src/whitelist.txt | awk '{print "$$"," = ", "\""$$0"\"", " fullword wide ascii nocase"}'
	@echo "extraction completed"

# dumps the yara rule as plain-text
dumps:
	cat $(filter-out $@,$(MAKECMDGOALS)) | grep '$ =' | awk '{print $$3 }' |  tr -d '"'

bundle: all
	yarac src/language-nsfw.yara $(DESTDIR)/language-nsfw.db
