# Negative Test Corpus

This directory contains negative test samples to validate that YARA NSFW rules do not produce false positives on legitimate, non-offensive content.

## Classic Literature Test Corpus

The test corpus consists of classic public domain literary works in multiple languages, sourced from [Project Gutenberg](https://www.gutenberg.org/).

These works are ideal for testing because:
- They contain rich, varied vocabulary in formal literary language
- They're a public domain and freely available
- They represent legitimate, non-offensive content that should NOT trigger NSFW detection
- They provide significant text volume for comprehensive testing

### Available Corpus Files

* English [Gutenberg #26](https://www.gutenberg.org/ebooks/26) |
* Spanish [Gutenberg #67092](https://www.gutenberg.org/ebooks/67092) |
* French [Gutenberg #13951](https://www.gutenberg.org/ebooks/13951) |
* Italian [Gutenberg #38720](https://www.gutenberg.org/ebooks/38720) |
* Dutch [Gutenberg #77745](https://www.gutenberg.org/ebooks/77745) 
* Portuguese [Gutenberg #16350](https://www.gutenberg.org/ebooks/16350)
* German [Gutenberg #77667](https://www.gutenberg.org/ebooks/77667)

**Total**: 7 languages covered with ~5.8 MB of authentic literary text

## Test Corpus Sources
Texts are sourced from public domain works via Project Gutenberg and Wikisource.
All literary content is in the public domain in the USA. 

### Languages Needing Corpus Files

The following languages still need test corpus files:

- Arabic (ar)
- Bengali (bn)
- Chinese (zh)
- Czech (cs)
- Danish (da)
- Esperanto (eo)
- Finnish (fi)
- German (de)
- Hindi (hi)
- Hungarian (hu)
- Japanese (ja)
- Korean (ko)
- Norwegian (no)
- Polish (pl)
- Russian (ru)
- Swedish (sv)
- Thai (th)
- Turkish (tr)
- English Racial (en-racial)

**Note**: Finding authentic native-language literary works on Project Gutenberg for these languages has proven challenging. Many books marked as being in these languages are actually English translations or have limited native text.

## Testing

These corpus files are used by the `make test` target to validate that NSFW rules produce zero false positives:

```bash
make test
```

The test suite:
1. Runs YARA rules against positive samples (should match NSFW content)
2. Runs YARA rules against negative samples (should NOT match legitimate content)
3. Fails if any negative sample produces a match (indicating a false positive)

## Adding New Test Corpora

To add test corpora for missing languages:

1. Find authentic native-language public domain literary text
   - Project Gutenberg: https://www.gutenberg.org/
   - Verify the book is actually in the target language (not a translation to English)
2. Save as `corpus_XX.txt` where XX is the language code
3. Ensure the file is UTF-8 encoded
4. Run `make test` to verify no false positives

### Verification

Before adding a corpus file, verify it's in the correct language:

```bash
# Check language metadata
head -50 corpus_XX.txt | grep -i "language:"

# Read actual text content to verify
head -100 corpus_XX.txt | tail -20
```

## Credits

All corpus files are sourced from [Project Gutenberg](https://www.gutenberg.org/) and are in the public domain.
