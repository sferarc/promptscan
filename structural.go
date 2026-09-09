package promptscan

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The structural layer reads codepoints, not meaning. Everything it reports has
// no ordinary explanation in database text, which is why these are the findings
// worth acting on.
//
// Each detector below is written against one question: what does the LEGITIMATE
// version of this look like? A detector that cannot answer that flags real
// customer data, gets switched off, and is then trusted in its off state, which
// is worse than never having shipped it.
//
// The sets below are switches rather than maps. They are consulted once per
// rune on every non-ASCII value, and a Go map lookup in that position was 26%
// of the profile; a switch over constants compiles to a binary search with no
// hashing and no map header load.

// isInvisible reports whether r renders as nothing.
//
// A stray one of these is ordinary (a soft hyphen from a word processor, a BOM
// from a CSV import), which is why detectInvisibleRun scores runs rather than
// presence. The lexical layer takes the opposite view and drops every one of
// them before matching, because a single invisible codepoint inside a word is
// enough to split a phrase in half.
func isInvisible(r rune) bool {
	switch r {
	case 0x00ad, // soft hyphen
		0x034f, // combining grapheme joiner
		0x061c, // arabic letter mark
		0x115f, // hangul choseong filler
		0x1160, // hangul jungseong filler
		0x17b4, // khmer vowel inherent aq
		0x17b5, // khmer vowel inherent aa
		0x180e, // mongolian vowel separator
		0x200b, // zero width space
		0x200c, // zero width non-joiner
		0x200d, // zero width joiner
		0x200e, // left-to-right mark
		0x200f, // right-to-left mark
		0x2060, // word joiner
		0x2061, // function application
		0x2062, // invisible times
		0x2063, // invisible separator
		0x2064, // invisible plus
		0x3164, // hangul filler
		0xfeff, // zero width no-break space
		0xffa0: // halfwidth hangul filler
		return true
	}
	return false
}

// isBidiOpen and isBidiClose split the bidirectional formatting codepoints by
// whether they need terminating. This split is the whole reason the detector is
// deployable: Arabic and Hebrew text legitimately carries these, and flagging
// their presence would flag every right-to-left customer record in the database.
func isBidiOpen(r rune) bool {
	switch r {
	case 0x202a, // left-to-right embedding
		0x202b, // right-to-left embedding
		0x202d, // left-to-right override
		0x202e, // right-to-left override
		0x2066, // left-to-right isolate
		0x2067, // right-to-left isolate
		0x2068: // first strong isolate
		return true
	}
	return false
}

func isBidiClose(r rune) bool {
	switch r {
	case 0x202c, // pop directional formatting
		0x2069: // pop directional isolate
		return true
	}
	return false
}

// isFormatNeutral reports whether r renders as nothing, so a reader looking at
// the value cannot see it and cannot see it end a word either.
//
// It is one predicate over the three sets above because both callers need
// exactly that union and they must not drift apart: normalizeForMatch drops
// these before matching a phrase, and detectMixedScript declines to end a word
// on one. Those are the same statement about the same codepoints, made once.
//
// The guard is exact rather than a heuristic: the lowest codepoint in any of
// the three sets is U+00AD, so no ASCII rune can be format-neutral and the
// space and the punctuation that end most words never reach the switches.
func isFormatNeutral(r rune) bool {
	if r < 0x00ad {
		return false
	}
	return isInvisible(r) || isBidiOpen(r) || isBidiClose(r)
}

// tagRunePrefixLo and tagRunePrefixHi are the three-byte prefixes of the UTF-8
// encoding of the Unicode Tag block: U+E0000 encodes as F3 A0 80 80 and U+E007F
// as F3 A0 81 BF, so every tag codepoint starts with F3 A0 80 or F3 A0 81.
//
// Two bytes would be cheaper to test and are wrong. F3 A0 alone also covers
// U+E0100 to U+E01EF, the Variation Selectors Supplement, which carries
// ideographic variation sequences in ordinary Japanese text. Gating on two
// bytes made a benign CJK value pay a full decode of itself and find nothing:
// 10.5ms and 1.18MB allocated for a 64KB value, reachable by any customer
// storing Japanese. The third byte separates the two blocks exactly.
var (
	tagRunePrefixLo = []byte{0xf3, 0xa0, 0x80}
	tagRunePrefixHi = []byte{0xf3, 0xa0, 0x81}
)

// isASCII reports whether every byte is below 0x80.
//
// This is the fast path that makes the structural layer affordable on ASCII,
// and it is exact rather than a heuristic: every technique this layer detects
// requires a non-ASCII codepoint. Invisible formatting starts at U+00AD,
// bidirectional controls at U+202A, Unicode Tags at U+E0000, and a script
// mixture needs letters from two scripts. A pure ASCII value cannot contain any
// of them, so skipping the detectors for one is not an approximation.
//
// It is also the only path the original benchmarks measured, which made the
// published cost of this layer the cost of this function. See bench_test.go.
func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

// scanStructural runs every byte-level and script-level detector.
func scanStructural(value []byte) []Finding {
	// Most database text is ASCII, and ASCII is provably clean for this layer.
	// Checking that first turns the common case into one linear pass with no
	// allocation, instead of four passes that each decode runes.
	if isASCII(value) {
		return nil
	}

	var findings []Finding
	if f, ok := detectTagSmuggling(value); ok {
		findings = append(findings, f)
	}
	if f, ok := detectInvisibleRun(value); ok {
		findings = append(findings, f)
	}
	if f, ok := detectUnbalancedBidi(value); ok {
		findings = append(findings, f)
	}
	if f, ok := detectMixedScript(value); ok {
		findings = append(findings, f)
	}
	return findings
}

// maxFlagTags bounds the buffer detectTagSmuggling holds while it decides
// whether a run of tag characters is an emoji subdivision flag. The longest
// sanctioned subdivision code is three characters and the format allows six, so
// a run past this length is not a flag whatever follows it, and the decision
// can be made without reading further.
const maxFlagTags = 8

// isFlagSubtag reports whether r is one of the tag characters an emoji
// subdivision flag is allowed to carry: the digits and the lowercase letters.
func isFlagSubtag(r rune) bool {
	return (r >= 0xe0030 && r <= 0xe0039) || (r >= 0xe0061 && r <= 0xe007a)
}

// detectTagSmuggling finds Unicode Tag codepoints. U+E0020 to U+E007E map one
// to one onto printable ASCII and render as nothing, so a whole instruction can
// sit in a cell that looks empty in every client.
//
// The block was deprecated for language tagging in Unicode 5.1 and has exactly
// one sanctioned use left: emoji subdivision flags, which encode a region code
// after a waving black flag. Those are the legitimate version, they DO occur in
// customer data (a shipping address, a profile, a product review), and the
// corpus caught this package flagging one before the exemption below existed.
// Everything else in the block is smuggling. The detector reports the decoded
// ASCII, because the decoded text is the finding.
//
// It runs as a single pass with a bounded buffer rather than decoding the value
// into a []rune plus a []int of byte offsets. The old shape allocated 12 bytes
// per input byte, so a value at the scan cap cost 1.18MB every time the prefix
// gate opened.
func detectTagSmuggling(value []byte) (Finding, bool) {
	// Tag codepoints are rare, and decoding the value to look for them would
	// cost a pass over every value scanned. Their UTF-8 encoding shares a
	// three-byte prefix that nothing outside the block uses, so two Contains
	// calls rule the block out without decoding anything.
	if !bytes.Contains(value, tagRunePrefixLo) && !bytes.Contains(value, tagRunePrefixHi) {
		return Finding{}, false
	}

	var decoded strings.Builder
	count := 0
	first := -1

	// note records one tag codepoint as smuggled.
	note := func(offset int, r rune) {
		if first < 0 {
			first = offset
		}
		count++
		if r >= 0xe0020 && r <= 0xe007e {
			decoded.WriteRune(r - 0xe0000)
		}
	}

	// A candidate emoji flag run: tag characters seen since a U+1F3F4 flag
	// base, held back until the run either terminates as a flag (discard) or
	// proves it is not one (report every one of them). The buffer is bounded by
	// maxFlagTags, so this stays allocation-free on the values that matter.
	type pendingTag struct {
		offset int
		r      rune
	}
	var candidate []pendingTag
	inCandidate := false
	prevWasFlagBase := false

	// flush reports every buffered candidate as smuggling.
	flush := func() {
		for _, p := range candidate {
			note(p.offset, p.r)
		}
		candidate = candidate[:0]
		inCandidate = false
	}

	for i, r := range string(value) {
		isTag := r >= 0xe0000 && r <= 0xe007f

		if inCandidate {
			switch {
			case isFlagSubtag(r):
				// Keep buffering, unless the run is already longer than any
				// real flag, in which case it cannot become one.
				if len(candidate) >= maxFlagTags {
					flush()
					note(i, r)
					prevWasFlagBase = false
					continue
				}
				candidate = append(candidate, pendingTag{offset: i, r: r})
				prevWasFlagBase = false
				continue
			case r == 0xe007f:
				// The terminator. A complete flag carries at least one subtag,
				// and an empty sequence is not a flag.
				if len(candidate) == 0 {
					note(i, r)
				} else {
					candidate = candidate[:0]
				}
				inCandidate = false
				prevWasFlagBase = false
				continue
			default:
				// Anything else ends the candidate without terminating it, so
				// the run was never a flag.
				flush()
			}
		}

		switch {
		case isTag && prevWasFlagBase:
			// Only a tag character immediately after the flag base can open a
			// flag sequence, which is the same rule the fuzz target re-derives.
			if isFlagSubtag(r) {
				inCandidate = true
				candidate = append(candidate, pendingTag{offset: i, r: r})
			} else {
				note(i, r)
			}
		case isTag:
			note(i, r)
		}
		prevWasFlagBase = r == 0x1f3f4
	}
	// Ran off the end with an unterminated candidate, so it was not a flag.
	flush()

	if count == 0 {
		return Finding{}, false
	}

	detail := fmt.Sprintf("%d Unicode Tag codepoints", count)
	if decoded.Len() > 0 {
		detail = fmt.Sprintf("%d Unicode Tag codepoints decoding to %q", count, truncate(decoded.String(), 64))
	}
	return Finding{
		Layer:      LayerStructural,
		Technique:  TechniqueTagSmuggling,
		Confidence: ConfidenceHigh,
		Offset:     first,
		Evidence:   truncate(decoded.String(), 64),
		Detail:     detail,
	}, true
}

// minInvisibleRun is how many consecutive invisible codepoints it takes before
// the run stops looking accidental. One is a stray import artifact. Two in a
// row does not happen by accident in prose, and a payload encoded as
// zero-width bits produces long runs.
//
// This threshold is right on its own and was wrong in combination, twice. A
// single invisible codepoint is genuinely not a structural finding, but it also
// used to end a word for both of the word-scoped detectors, so one U+200B
// defeated the layer that was supposed to cover for this one. It split a phrase
// in half for the lexical layer, and it split a spoofed token into two
// single-script halves for detectMixedScript.
//
// Both are fixed at the point of comparison rather than here, through
// isFormatNeutral: normalizeForMatch drops those codepoints before matching and
// detectMixedScript declines to end a word on one. The threshold stays as it
// is, because a value whose only anomaly is one invisible character still has
// nothing structural to report about that character.
const minInvisibleRun = 2

// detectInvisibleRun finds runs of invisible codepoints. It scores runs rather
// than presence, because a single soft hyphen or BOM is ordinary in data that
// has been through a word processor or a CSV export.
func detectInvisibleRun(value []byte) (Finding, bool) {
	longest := 0
	longestAt := -1
	total := 0

	run := 0
	runAt := -1
	for i, r := range string(value) {
		if isInvisible(r) {
			if run == 0 {
				runAt = i
			}
			run++
			total++
			if run > longest {
				longest = run
				longestAt = runAt
			}
			continue
		}
		run = 0
	}

	if longest < minInvisibleRun {
		return Finding{}, false
	}

	// A long run, or many of them, is a payload rather than an artifact.
	confidence := ConfidenceMedium
	if longest >= 8 || total >= 16 {
		confidence = ConfidenceHigh
	}
	return Finding{
		Layer:      LayerStructural,
		Technique:  TechniqueInvisibleRun,
		Confidence: confidence,
		Offset:     longestAt,
		Evidence:   renderInvisible(contextAround(value, longestAt, 24)),
		Detail: fmt.Sprintf(
			"%d invisible codepoints, longest run %d",
			total, longest,
		),
	}, true
}

// detectUnbalancedBidi finds bidirectional overrides that are never terminated.
//
// Balanced marks are how right-to-left text works, so presence proves nothing.
// An override left open at the end of a value is what makes rendered text
// differ from stored text for everything that follows it, which is the trick.
func detectUnbalancedBidi(value []byte) (Finding, bool) {
	depth := 0
	firstOpen := -1
	sawOverride := false

	for i, r := range string(value) {
		switch {
		case isBidiOpen(r):
			if depth == 0 {
				firstOpen = i
			}
			if r == 0x202d || r == 0x202e {
				sawOverride = true
			}
			depth++
		case isBidiClose(r):
			if depth > 0 {
				depth--
			}
		}
	}
	if depth == 0 {
		return Finding{}, false
	}

	// An unterminated embedding or isolate is often sloppy authoring. An
	// unterminated OVERRIDE is the one that reorders arbitrary following text.
	confidence := ConfidenceMedium
	if sawOverride {
		confidence = ConfidenceHigh
	}
	return Finding{
		Layer:      LayerStructural,
		Technique:  TechniqueBidiOverride,
		Confidence: confidence,
		Offset:     firstOpen,
		Evidence:   renderInvisible(contextAround(value, firstOpen, 24)),
		Detail: fmt.Sprintf(
			"%d unterminated bidirectional control(s), so display order differs from stored order",
			depth,
		),
	}, true
}

// script is the coarse family a letter belongs to, for confusability purposes
// only. It is not the Unicode script property and does not try to be.
type script uint8

const (
	scriptOther script = iota
	scriptLatin
	scriptCyrillic
	scriptGreek
	scriptArmenian
	scriptCherokee
)

func (s script) String() string {
	switch s {
	case scriptLatin:
		return "Latin"
	case scriptCyrillic:
		return "Cyrillic"
	case scriptGreek:
		return "Greek"
	case scriptArmenian:
		return "Armenian"
	case scriptCherokee:
		return "Cherokee"
	}
	return "other"
}

// confusableScriptOf classifies a letter into the family cluster that can spoof
// Latin, and returns scriptOther for everything else.
//
// The cluster is deliberately closed. Han, Kana, Hangul, Arabic, Hebrew and the
// Indic scripts cannot be mistaken for Latin letters at any size, so a word
// mixing one of them with Latin is ordinary content rather than a spoof. This
// is what keeps "iPhone用" and "ビタミンC" and "A型" from flagging, and treating
// every script as confusable would flag all three.
func confusableScriptOf(r rune) script {
	if r < utf8.RuneSelf {
		// The overwhelmingly common case, and the one unicode.Is is slowest at.
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return scriptLatin
		}
		return scriptOther
	}
	// The main blocks, checked directly before falling back to the range
	// tables. unicode.Is walks a table of several hundred ranges, and the
	// fallback order made Cyrillic the most expensive script to classify: every
	// letter of a Russian value searched the whole Latin table first and missed.
	// Ordinary text in these scripts lives almost entirely in these blocks.
	switch {
	case r >= 0x00c0 && r <= 0x024f: // Latin-1 Supplement through Latin Extended-B
		if unicode.IsLetter(r) {
			return scriptLatin
		}
		return scriptOther
	case r >= 0x0370 && r <= 0x03ff: // Greek and Coptic
		if unicode.IsLetter(r) {
			return scriptGreek
		}
		return scriptOther
	case r >= 0x0400 && r <= 0x04ff: // Cyrillic
		if unicode.IsLetter(r) {
			return scriptCyrillic
		}
		return scriptOther
	case r >= 0x0530 && r <= 0x058f: // Armenian
		if unicode.IsLetter(r) {
			return scriptArmenian
		}
		return scriptOther
	}

	switch {
	case unicode.Is(unicode.Latin, r):
		return scriptLatin
	case unicode.Is(unicode.Cyrillic, r):
		return scriptCyrillic
	case unicode.Is(unicode.Greek, r):
		return scriptGreek
	case unicode.Is(unicode.Armenian, r):
		return scriptArmenian
	case unicode.Is(unicode.Cherokee, r):
		return scriptCherokee
	}
	return scriptOther
}

// isLatinLookalike reports whether r is drawn so nearly identically to a Latin
// letter that a reader cannot tell them apart in ordinary text.
//
// This test is what replaced "the word contains letters from two scripts", and
// the replacement is the whole false-positive fix. Cross-script mixture on its
// own flags the way science is written: TNFα, IL2Rα, PPARγ, NFκB, Aβ42, μmol/L,
// 4.7kΩ and ΔT are ordinary values in a life-sciences, chemistry or engineering
// database, and every one of them was reported at HIGH confidence before this
// existed. None is a spoof, because alpha, beta, gamma, kappa, mu, Delta and
// Omega do not look like any Latin letter. A spoof needs a glyph the reader
// cannot distinguish.
//
// So lowercase Greek is out of this set except omicron and lunate sigma, which
// genuinely are indistinguishable from o and c. That is a real and stated gap:
// rho, nu, chi and upsilon are close enough to p, v, x and u to fool a hurried
// reader, and they are excluded anyway, because spectroscopy writes νmax and
// statistics writes χ². The lexical layer still folds all four (see
// confusableToLatin), so a homoglyph substitution using them inside a known
// phrase is still caught there. It is the structural layer, the one whose
// findings are meant to be acted on unattended, that declines to guess.
//
// Which codepoint a customer stores is not their choice either: micro sign
// U+00B5 is script Common while mu U+03BC is Greek, the two are the same
// character to a reader, and an ETL pipeline decides which one lands in the
// column. Neither is in this set, so neither can decide whether a row is
// flagged.
func isLatinLookalike(r rune) bool {
	switch r {
	// Cyrillic lowercase drawn identically to Latin.
	case 'а', 'в', 'е', 'к', 'м', 'н', 'о', 'р', 'с', 'т', 'у', 'х',
		'і', 'ј', 'ѕ', 'һ', 'ԁ', 'ԛ', 'ԝ', 'ѵ', 'ԍ', 'ё':
		return true
	// Cyrillic uppercase drawn identically to Latin.
	case 'А', 'В', 'Е', 'К', 'М', 'Н', 'О', 'Р', 'С', 'Т', 'У', 'Х',
		'І', 'Ј', 'Ѕ', 'Ԁ', 'Ԝ', 'Ё',
		// Һ and Ԛ are drawn as H and Q. Their lowercase twins һ and ԛ were
		// already on the list above, so an all-caps word was the only spelling
		// of the same spoof this detector did not see.
		'Һ', 'Ԛ':
		return true
	// Greek uppercase drawn identically to Latin. The Greek capitals science
	// actually uses (Delta, Sigma, Pi, Omega, Phi, Psi, Gamma, Lambda, Theta,
	// Xi) are all absent from this list, which is why they no longer flag.
	case 'Α', 'Β', 'Ε', 'Ζ', 'Η', 'Ι', 'Κ', 'Μ', 'Ν', 'Ο', 'Ρ', 'Τ', 'Υ', 'Χ':
		return true
	// Greek lowercase, only the two that are genuinely indistinguishable.
	case 'ο', 'ϲ':
		return true
	// Armenian drawn like Latin. These bypassed the detector entirely when it
	// counted only three families, because an Armenian letter set no family at
	// all and "ignօre" scored as a Latin-only word.
	case 'օ', 'ո', 'ս', 'ց', 'գ', 'ր', 'ա', 'ք':
		return true
	// Armenian capitals, which are separate glyphs rather than larger versions
	// of the row above, so only the two that pass the same bar are here: Օ is
	// drawn as O and Ս is drawn as U. "IGNՕRE ALL PREVIOUS INSTRUCTIONS" read
	// clean while "ignօre all previous instructions" was reported at high
	// confidence, on the same letter in the other case. The rest of the
	// Armenian capitals (Ա, Գ, Ն, Ո, Ր, Ց, Ք) are deliberately absent: none of
	// them is drawn like a Latin capital, and guessing here is how a detector
	// meant to be acted on unattended starts flagging Armenian records.
	case 'Օ', 'Ս':
		return true
	// Cherokee drawn like Latin capitals, same story.
	case 'Ꭰ', 'Ꭱ', 'Ꭲ', 'Ꭺ', 'Ꭻ', 'Ꭼ', 'Ꮃ', 'Ꮇ', 'Ꮋ', 'Ꮍ', 'Ᏻ', 'Ꮖ', 'Ꮪ', 'Ꮯ':
		return true
	}
	// A Latin letter is a lookalike from the other direction: a stray Latin
	// character inside an otherwise Cyrillic or Greek word is the same spoof
	// run backwards, as in a bank name spelled with one Latin "a" in it. This
	// only fires when Latin is the MINORITY script of a word whose dominant
	// script is also in the confusable cluster, so it cannot reach "ビタミンC".
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// detectMixedScript finds single words that mix scripts which render alike.
//
// The scoping to a WORD is what makes this usable at all. "Пётр Ильич" is a
// name and every letter is Cyrillic. "раypal" is an attack and mixes Cyrillic
// with Latin inside one token. Checking the whole value for the presence of
// Cyrillic would flag every Russian customer; checking each word for a mixture
// flags only the construction that has no honest reading.
func detectMixedScript(value []byte) (Finding, bool) {
	// start is where the current word began and end is one past its last word
	// rune. They are tracked separately because a format codepoint may sit
	// inside the word without being part of its edges.
	start, end := -1, -1

	// closeWord judges the word just ended, and does nothing when there was not
	// one. A value can hold format codepoints and punctuation and no word at
	// all, which is the case start < 0 covers.
	closeWord := func() (Finding, bool) {
		if start < 0 {
			return Finding{}, false
		}
		return mixedScriptWord(value[start:end], start)
	}

	// Ranging over string(value) rather than converting first: the compiler
	// recognizes this exact form and iterates the bytes in place. The value is
	// already known to be valid UTF-8 (scanWithin checks before any detector
	// runs), so RuneLen below is the width the loop actually consumed.
	for i, r := range string(value) {
		switch {
		case isWordRune(r):
			if start < 0 {
				start = i
			}
			end = i + utf8.RuneLen(r)
		case isFormatNeutral(r):
			// Renders as nothing, so it does not end a word for the reader and
			// must not end one here. Ending on it is what let a single U+200B
			// cut "раypal" into a Cyrillic half and a Latin half, each of them
			// single-script and each of them unobjectionable, which is the
			// whole spoof surviving one invisible codepoint. It is not added to
			// the word's edges either: a leading or trailing one belongs to no
			// word.
		default:
			if f, ok := closeWord(); ok {
				return f, true
			}
			start, end = -1, -1
		}
	}
	if f, ok := closeWord(); ok {
		return f, true
	}
	return Finding{}, false
}

// isWordRune reports whether r continues a word for mixed-script purposes.
// Digits and marks are script-neutral and are included so "Кириллица2" is one
// word rather than two, which keeps the neutral characters from splitting a
// token and hiding a mixture.
func isWordRune(r rune) bool {
	if r < utf8.RuneSelf {
		// unicode.IsMark has no Latin-1 fast path and was a measurable part of
		// the per-rune cost. No ASCII codepoint is a mark.
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r)
}

// mixedScriptWord reports a finding when one word carries a letter from a
// script other than its dominant one AND that letter is drawn like a Latin
// letter.
//
// Both halves are load-bearing. Mixture alone is how science is written. A
// lookalike alone is just a letter. Together they describe a token that reads
// as one word and is spelled as another, which has no honest reading.
func mixedScriptWord(word []byte, offset int) (Finding, bool) {
	var counts [scriptCherokee + 1]int
	letters := 0

	for _, r := range string(word) {
		if !unicode.IsLetter(r) {
			continue
		}
		letters++
		counts[confusableScriptOf(r)]++
	}

	// A single letter cannot be a mixture, and a word of one letter beside a
	// digit is a label rather than a spoof.
	if letters < 2 {
		return Finding{}, false
	}

	// Count only the families that can spoof each other. A word that is Latin
	// plus Han is not a mixture for this purpose.
	families := 0
	dominant := scriptOther
	best := 0
	for s := scriptLatin; s <= scriptCherokee; s++ {
		if counts[s] == 0 {
			continue
		}
		families++
		// Ties resolve to Latin, which is the script these databases are
		// written in, so a Latin letter is never the minority by accident. This
		// is what keeps the two-letter cases (ΔT, Ωm) from flagging either way
		// round.
		if counts[s] > best || (counts[s] == best && s == scriptLatin) {
			best = counts[s]
			dominant = s
		}
	}
	if families < 2 {
		return Finding{}, false
	}

	for _, r := range string(word) {
		if !unicode.IsLetter(r) {
			continue
		}
		s := confusableScriptOf(r)
		if s == scriptOther || s == dominant {
			continue
		}
		if !isLatinLookalike(r) {
			continue
		}
		return Finding{
			Layer:      LayerStructural,
			Technique:  TechniqueMixedScript,
			Confidence: ConfidenceHigh,
			Offset:     offset,
			Evidence:   truncate(string(word), 48),
			Detail: fmt.Sprintf(
				"the word %q is mostly %s but carries %s %q, which is drawn the same way",
				truncate(string(word), 32), dominant, s, string(r),
			),
		}, true
	}
	return Finding{}, false
}

// contextAround returns up to width bytes on each side of a byte offset, cut to
// rune boundaries so the result is printable.
func contextAround(value []byte, offset, width int) string {
	if offset < 0 || offset > len(value) {
		return ""
	}
	lo := max(offset-width, 0)
	for lo > 0 && !utf8.RuneStart(value[lo]) {
		lo--
	}
	hi := min(offset+width, len(value))
	for hi < len(value) && !utf8.RuneStart(value[hi]) {
		hi++
	}
	return string(value[lo:hi])
}

// renderInvisible makes control and invisible codepoints visible so evidence can
// be logged, shown in a terminal and pasted into a ticket without vanishing.
// Evidence that renders as nothing is not evidence.
func renderInvisible(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || (r >= 0x7f && r < 0xa0):
			fmt.Fprintf(&b, `\x%02x`, r)
		case isInvisible(r) || isBidiOpen(r) || isBidiClose(r) || (r >= 0xe0000 && r <= 0xe007f):
			fmt.Fprintf(&b, "<U+%04X>", r)
		default:
			b.WriteRune(r)
		}
	}
	return truncate(b.String(), 96)
}

// truncate cuts s to at most max bytes on a rune boundary, marking the cut.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
