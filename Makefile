# yara sources
SOURCES = en-language-nsfw.yara ar-language-nsfw.yara
OUTPUT_DIR = dist

all: deps
	$(foreach source,$(SOURCES),yarac src/$(source) $(OUTPUT_DIR)/$(source).db;)

deps:
	mkdir -p $(OUTPUT_DIR)

clean:
	rm -rf $(OUTPUT_DIR)

# extracts string content from a text file into yara-like format
extract:
	cat $(filter-out $@,$(MAKECMDGOALS)) | awk '{print "$$s"NR," = ", "\""$$0"\"", " fullword wide ascii nocase"}'

# dumps the yara rule as plain-text
dumps:
	cat $(filter-out $@,$(MAKECMDGOALS)) | grep '$$s' | awk '{print $$3 }' |  tr -d '"'

bundle:
	yarac src/safe-language.yara $(OUTPUT_DIR)/safe-language.db
