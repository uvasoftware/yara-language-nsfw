## List of NSFW (not suitable for work) language in YARA(http://virustotal.github.io/yara/) pattern-matching format
_based upon work from https://github.com/LDNOOBW/List-of-Dirty-Naughty-Obscene-and-Otherwise-Bad-Words_
_this database powers the nsfw language feature of the https://scanii.com content analysis service_

### Compiling the rules
`$ make
 mkdir -p dist
 yarac src/cs-language-nsfw.yara dist/cs-language-nsfw.yara.db; yarac src/da-language-nsfw.yara dist/da-language-nsfw.yara.db; yarac src/de-language-nsfw.yara dist/de-language-nsfw.yara.db; yarac src/en-language-nsfw.yara dist/en-language-nsfw.yara.db; yarac src/eo-language-nsfw.yara dist/eo-language-nsfw.yara.db; yarac src/es-language-nsfw.yara dist/es-language-nsfw.yara.db; yarac src/fi-language-nsfw.yara dist/fi-language-nsfw.yara.db; yarac src/fr-language-nsfw.yara dist/fr-language-nsfw.yara.db; yarac src/hi-language-nsfw.yara dist/hi-language-nsfw.yara.db; yarac src/hu-language-nsfw.yara dist/hu-language-nsfw.yara.db; yarac src/it-language-nsfw.yara dist/it-language-nsfw.yara.db; yarac src/ja-language-nsfw.yara dist/ja-language-nsfw.yara.db; yarac src/ko-language-nsfw.yara dist/ko-language-nsfw.yara.db; yarac src/nl-language-nsfw.yara dist/nl-language-nsfw.yara.db; yarac src/no-language-nsfw.yara dist/no-language-nsfw.yara.db; yarac src/pl-language-nsfw.yara dist/pl-language-nsfw.yara.db; yarac src/pt-language-nsfw.yara dist/pt-language-nsfw.yara.db; yarac src/ru-language-nsfw.yara dist/ru-language-nsfw.yara.db; yarac src/sv-language-nsfw.yara dist/sv-language-nsfw.yara.db; yarac src/th-language-nsfw.yara dist/th-language-nsfw.yara.db; yarac src/tlh-language-nsfw.yara dist/tlh-language-nsfw.yara.db; yarac src/tr-language-nsfw.yara dist/tr-language-nsfw.yara.db; yarac src/zh-language-nsfw.yara dist/zh-language-nsfw.yara.db;
 `
### Creating single bundle rule
`
$ make bundle
mkdir -p dist
yarac src/cs-language-nsfw.yara dist/cs-language-nsfw.yara.db; yarac src/da-language-nsfw.yara dist/da-language-nsfw.yara.db; yarac src/de-language-nsfw.yara dist/de-language-nsfw.yara.db; yarac src/en-language-nsfw.yara dist/en-language-nsfw.yara.db; yarac src/eo-language-nsfw.yara dist/eo-language-nsfw.yara.db; yarac src/es-language-nsfw.yara dist/es-language-nsfw.yara.db; yarac src/fi-language-nsfw.yara dist/fi-language-nsfw.yara.db; yarac src/fr-language-nsfw.yara dist/fr-language-nsfw.yara.db; yarac src/hi-language-nsfw.yara dist/hi-language-nsfw.yara.db; yarac src/hu-language-nsfw.yara dist/hu-language-nsfw.yara.db; yarac src/it-language-nsfw.yara dist/it-language-nsfw.yara.db; yarac src/ja-language-nsfw.yara dist/ja-language-nsfw.yara.db; yarac src/ko-language-nsfw.yara dist/ko-language-nsfw.yara.db; yarac src/nl-language-nsfw.yara dist/nl-language-nsfw.yara.db; yarac src/no-language-nsfw.yara dist/no-language-nsfw.yara.db; yarac src/pl-language-nsfw.yara dist/pl-language-nsfw.yara.db; yarac src/pt-language-nsfw.yara dist/pt-language-nsfw.yara.db; yarac src/ru-language-nsfw.yara dist/ru-language-nsfw.yara.db; yarac src/sv-language-nsfw.yara dist/sv-language-nsfw.yara.db; yarac src/th-language-nsfw.yara dist/th-language-nsfw.yara.db; yarac src/tlh-language-nsfw.yara dist/tlh-language-nsfw.yara.db; yarac src/tr-language-nsfw.yara dist/tr-language-nsfw.yara.db; yarac src/zh-language-nsfw.yara dist/zh-language-nsfw.yara.db;
yarac src/language-nsfw.yara dist/language-nsfw.db
`
this will create a single langauge-nsfw.db compiled yara rule with all the individual languages

### Converting from YARA to plain text

Makefile rules are provided to make it easy for you to convert to and from plain text files

`
$ make dumps src/ja-language-nsfw.yara 
cat src/ja-language-nsfw.yara | grep '=' | awk '{print $3 }' |  tr -d '"'
3p
g
s
sm
sm女王
xx
卍
糞
膣
裸
お尻
なめ
グロ
デブ
ホモ
`

### Converting from plain text to YARA

`
$ make extract /tmp/list.txt 
cat /tmp/list.txt | sort | uniq -u | grep -v -x -f src/whitelist.txt | awk '{print "$"," = ", "\""$0"\"", " fullword wide ascii nocase"}'
$  =  "hello"  fullword wide ascii nocase
$  =  "world"  fullword wide ascii nocase
extraction completed
`

### Using signature database

`
$yara dist/language-nsfw.db nsfw-language-sample.txt 
content_da_language_nsfw nsfw-language-sample.txt
content_en_language_nsfw nsfw-language-sample.txt
content_nl_language_nsfw nsfw-language-sample.txt
`
