# YARA NSFW Language Detection Rules

A comprehensive collection of NSFW (not suitable for work) language detection rules in [YARA](http://virustotal.github.io/yara/) pattern-matching format.

This database powers the NSFW language detection feature of the [Scanii](https://www.scanii.com) content analysis service.

## Supported Languages

This project includes NSFW language detection rules for **25 languages**:

| Language | Code | Language | Code |
|----------|------|----------|------|
| Arabic | `ar` | Italian | `it` |
| Bengali | `bn` | Japanese | `ja` |
| Chinese | `zh` | Korean | `ko` |
| Czech | `cs` | Dutch | `nl` |
| Danish | `da` | Norwegian | `no` |
| English | `en` | Polish | `pl` |
| English (Racial) | `en-racial` | Portuguese | `pt` |
| Esperanto | `eo` | Russian | `ru` |
| Finnish | `fi` | Swedish | `sv` |
| French | `fr` | Thai | `th` |
| German | `de` | Turkish | `tr` |
| Hindi | `hi` | Hungarian | `hu` |
| Spanish | `es` | | |

## Rule Format

All rules use **hex-encoded strings** to ensure proper character encoding across different platforms and avoid issues with special characters. This is especially important for languages with non-ASCII characters.

### Example Rule Structure

```yara
rule content_en_language_nsfw_42 {
  meta:
    info = "badword"
  strings:
    $ascii1 = "\x66\x75\x63\x6b" nocase  // "badword" in ASCII/UTF-8
    $wide1 = "\x66\x00\x75\x00\x63\x00\x6b\x00" nocase  // "badword" in UTF-16LE
  condition:
    any of them
}
```

### Why Hex Encoding?

1. **Character Encoding Safety**: Hex encoding ensures characters are interpreted correctly regardless of file encoding
2. **Special Character Support**: Handles accented characters (é, ñ, ü) and non-Latin scripts (Arabic, Chinese, etc.)
3. **Multiple Encodings**: Each rule typically includes patterns for:
   - UTF-8 (`$utf8`)
   - Latin-1 (`$latin1`)
   - Windows CP-1252 (`$cp1252`)
   - UTF-16LE/Wide strings (`$wide`)

### Creating New Rules

When adding new words, convert them to hex:

```bash
# For ASCII/UTF-8:
echo -n "word" | xxd -p | sed 's/../\\x&/g'

# For UTF-16LE (wide):
echo -n "word" | iconv -t UTF-16LE | xxd -p | sed 's/../\\x&/g'
```

#### Compiling the rules

```
% make build
mkdir -p ./dist
yarac src/entrypoint.yara ./dist/language-nsfw.db
```

#### Running tests 

```
% make test
mkdir -p ./dist
yarac src/entrypoint.yara ./dist/language-nsfw.db
...
```

## Credits:
This codebase started as a fork from [List of Dirty, Naughty, Obscene, and Otherwise Bad Words](https://github.com/LDNOOBW/List-of-Dirty-Naughty-Obscene-and-Otherwise-Bad-Words) .
