# Changelog

## 0.2.2

### Patch Changes

- 7a03930: fix(scan): a mixed-script finding handed back its word raw, so a bidi override in it reordered whatever read the evidence

## 0.2.1

### Patch Changes

- 201dbf4: fix(scan): one invisible codepoint split a spoofed word in half and the mixed-script detector had nothing left to see

## 0.2.0

### Minor Changes

- 87b67d9: feat(scan): a budget that spans values, so a scan can bound a result set and not just a value

## 0.1.1

### Patch Changes

- d24577b: fix(scan): a homoglyph substitution was caught in lowercase and missed in capitals

## 0.1.0

First public release.

- `Scanner` with two detector layers, structural and lexical, selected by `Config`.
- Structural detection of invisible codepoint runs, Unicode Tag smuggling, unterminated bidirectional overrides, and mixed-script words.
- Lexical phrase matching over Aho-Corasick, with NFKC and confusable folding so a payload written in fullwidth or Cyrillic lookalikes still matches. Off by default.
- Three verdicts, `clean`, `suspicious` and `unscannable`, so a value that could not be read is never reported as one nobody objected to.
- Findings name the layer, the technique and an ordered confidence, and quote the offending bytes with invisible codepoints rendered visible.
