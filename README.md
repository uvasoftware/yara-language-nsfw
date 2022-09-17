### List of NSFW (not suitable for work) language in [YARA](http://virustotal.github.io/yara/) pattern-matching format

→ based upon work from https://github.com/LDNOOBW/List-of-Dirty-Naughty-Obscene-and-Otherwise-Bad-Words

→ this database powers the nsfw language feature of the https://scanii.com content analysis service

#### Compiling the rules

```
% make build
mkdir -p ./dist
yarac src/entrypoint.yara ./dist/language-nsfw.db
```
