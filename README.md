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

All rules use **hex-encoded strings** with the **`fullword`** modifier to ensure proper character encoding and prevent false positives from partial word matches.

### Example Rule Structure

```yara
rule content_en_language_nsfw_65 {
  meta:
    info = "fuck"
  strings:
    $ascii = "\x66\x75\x63\x6b" nocase fullword  // "fuck" in ASCII/UTF-8
    $wide = "\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // "fuck" in UTF-16LE
  condition:
    any of them
}
```

### Key Rule Features

#### 1. Hex Encoding
All strings are hex-encoded for reliability:
- **Character Encoding Safety**: Ensures correct interpretation regardless of file encoding
- **Special Character Support**: Handles accented characters (é, ñ, ü) and non-Latin scripts (Arabic, Chinese, etc.)
- **Cross-Platform Consistency**: Works identically on all systems

#### 2. Fullword Matching
The `fullword` modifier ensures rules only match complete words, preventing false positives:
- `"ass"` will match `"ass"` but **not** `"class"`, `"pass"`, or `"grass"`
- `"hell"` will match `"hell"` but **not** `"hello"` or `"shell"`
- Word boundaries are defined by transitions between word characters (`[a-zA-Z0-9_]`) and non-word characters

#### 3. Multiple Encodings
Rules include patterns for different character encodings to ensure comprehensive detection across legacy and modern documents:

| Encoding | Variable | When Required | Example Languages |
|----------|----------|---------------|-------------------|
| **UTF-8** | `$utf8` or `$ascii` | Always (universal modern standard) | All languages |
| **UTF-16LE** | `$wide` | Always (Windows, databases) | All languages |
| **Latin-1 (ISO-8859-1)** | `$latin1` | For Western European languages with accents | French, Spanish, Portuguese, Italian, German, Swedish, Danish, Norwegian |
| **CP-1252** | `$cp1252` | For Windows legacy documents | Same as Latin-1 (nearly identical) |
| **CP-1256** | `$cp1256` | For Arabic legacy documents | Arabic |
| **CP-1251** | `$cp1251` | For Cyrillic legacy documents | Russian |
| **Shift-JIS** | `$sjis` | For Japanese legacy documents | Japanese |
| **GBK** | `$gbk` | For Chinese legacy documents | Chinese (Simplified) |

#### Why Multiple Encodings?

**For ASCII-only text (English with no accents):**
- UTF-8, Latin-1, and CP-1252 are **identical** in the ASCII range (0x00-0x7F)
- Only UTF-8 and UTF-16LE patterns are needed
- Example: `"fuck"` is `\x66\x75\x63\x6b` in all three encodings

**For text with accented characters (é, ö, ñ, etc.):**
- UTF-8 uses multi-byte sequences: `é` = `\xc3\xa9`
- Latin-1/CP-1252 use single bytes: `é` = `\xe9`
- Both patterns are needed to detect the word in legacy vs. modern documents
- Example: French `"merde"` vs `"merdé"`

**For non-Latin scripts:**
- Specialized encodings (CP-1256 for Arabic, GBK for Chinese, etc.) are required for legacy documents
- UTF-8 and UTF-16LE handle modern documents

### Creating New Rules

When adding new words, convert them to hex encoding:

```bash
# For ASCII/UTF-8:
echo -n "word" | xxd -p | sed 's/../\\x&/g'

# For UTF-16LE (wide):
echo -n "word" | iconv -t UTF-16LE | xxd -p | sed 's/../\\x&/g'

# For Latin-1 (if word contains é, ñ, ö, etc.):
echo -n "word" | iconv -t ISO-8859-1 | xxd -p | sed 's/../\\x&/g'
```

**Rule Template:**

```yara
rule content_XX_language_nsfw_N {
  meta:
    info = "word"
  strings:
    $utf8 = "\x..." nocase fullword     // UTF-8 encoding
    $latin1 = "\x..." nocase fullword   // Latin-1 (if needed)
    $cp1252 = "\x..." nocase fullword   // CP-1252 (if needed)
    $wide = "\x...\x00..." nocase fullword  // UTF-16LE
  condition:
    any of them
}
```

**Important:**
- Always include the `fullword` modifier to prevent partial matches
- Include `nocase` for case-insensitive matching
- UTF-8 and UTF-16LE are **required** for all rules
- Latin-1/CP-1252 are **optional** but recommended for Western European languages with accented characters

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
