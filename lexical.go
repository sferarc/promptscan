package promptscan

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cloudflare/ahocorasick"
	"golang.org/x/text/unicode/norm"
)

// The lexical layer matches wording. It is the layer that produces false
// positives and it is reported at low confidence for that reason.
//
// The problem is not that the phrases are wrong. It is that the most likely
// place to find the exact string "ignore all previous instructions" in a
// customer database is a support ticket about prompt injection, a security
// advisory, or a bug report quoting the payload. Those are the rows a security
// vendor's own customers are most likely to have. So a lexical hit is a reason
// to look, never a reason to act, and the package documentation says so.
//
// It uses Aho-Corasick so the cost is one pass over the value regardless of how
// many phrases are configured, rather than one pass per phrase.

// phraseMatcher holds the compiled phrase set.
type phraseMatcher struct {
	matcher *ahocorasick.Matcher
	// phrases holds the caller's original spelling, for evidence.
	phrases []string
	// normalized holds the same phrases in the form values are matched
	// against, so a hit can be re-located to check its word boundaries.
	normalized []string
}

// ErrEmptyPhrase is returned when a configured phrase is empty or only
// whitespace. It is an error rather than a skip: a phrase list that quietly
// shrank is a scanner that quietly stopped looking for something.
var ErrEmptyPhrase = errors.New("promptscan: phrase list contains an empty entry")

// newPhraseMatcher compiles a phrase set. Phrases are normalized the same way
// scanned values are, so a phrase written with ordinary characters still
// matches a value written with fullwidth or Cyrillic lookalikes.
func newPhraseMatcher(phrases []string) (*phraseMatcher, error) {
	if len(phrases) == 0 {
		return nil, errors.New("promptscan: lexical layer enabled with no phrases")
	}

	normalized := make([]string, 0, len(phrases))
	kept := make([]string, 0, len(phrases))
	seen := make(map[string]bool, len(phrases))

	for i, p := range phrases {
		n := normalizeForMatch(p)
		if strings.TrimSpace(n) == "" {
			return nil, fmt.Errorf("%w: entry %d is %q", ErrEmptyPhrase, i, p)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		normalized = append(normalized, n)
		kept = append(kept, p)
	}

	return &phraseMatcher{
		matcher:    ahocorasick.NewStringMatcher(normalized),
		phrases:    kept,
		normalized: normalized,
	}, nil
}

// scan reports one finding per distinct phrase found.
//
// Offsets are not reported. Matching runs against a normalized copy, so an
// offset into it does not address the original bytes, and a wrong offset in
// evidence is worse than none. The matched phrase is the evidence.
func (m *phraseMatcher) scan(value []byte) []Finding {
	normalized := normalizeForMatch(string(value))

	// MatchThreadSafe rather than Match: a Scanner is shared across
	// connections, and Match mutates matcher state.
	hits := m.matcher.MatchThreadSafe([]byte(normalized))
	if len(hits) == 0 {
		return nil
	}

	findings := make([]Finding, 0, len(hits))
	for _, idx := range hits {
		if idx < 0 || idx >= len(m.phrases) {
			continue
		}
		// Aho-Corasick reports substring hits, which is how "system:" matched
		// "filesystem:", "subsystem:" and "ecosystem:". It returns which
		// patterns matched rather than where, so the boundary check re-locates
		// the phrase. Hits are rare, so paying a scan per hit is free in the
		// case that matters.
		if !hasWordBoundary(normalized, m.normalized[idx]) {
			continue
		}
		findings = append(findings, Finding{
			Layer:      LayerLexical,
			Technique:  TechniqueInstructionPhrase,
			Confidence: ConfidenceLow,
			Offset:     -1,
			Evidence:   m.phrases[idx],
			Detail: fmt.Sprintf(
				"contains the phrase %q, which is common in instruction-override text and also in writing about it",
				m.phrases[idx],
			),
		})
	}
	if len(findings) == 0 {
		return nil
	}
	return findings
}

// hasWordBoundary reports whether phrase occurs in haystack at least once with
// a word boundary on each side, so a phrase is not matched inside a longer
// word. Both strings are already normalized.
func hasWordBoundary(haystack, phrase string) bool {
	if phrase == "" {
		return false
	}
	for from := 0; from+len(phrase) <= len(haystack); {
		i := strings.Index(haystack[from:], phrase)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(phrase)
		if !alnumAdjacent(haystack, start, -1) && !alnumAdjacent(haystack, end, +1) {
			return true
		}
		from = start + 1
	}
	return false
}

// alnumAdjacent reports whether the character immediately before (dir -1) or at
// (dir +1) the given byte index is a letter or digit, which is what makes the
// position the middle of a word rather than its edge.
func alnumAdjacent(s string, at, dir int) bool {
	if dir < 0 {
		if at <= 0 {
			return false
		}
		r, _ := utf8.DecodeLastRuneInString(s[:at])
		return unicode.IsLetter(r) || unicode.IsDigit(r)
	}
	if at >= len(s) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s[at:])
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// normalizeForMatch folds a value into the form phrases are compared against:
// invisible codepoints removed, compatibility-normalized, confusables folded to
// Latin, lowercased, and whitespace collapsed.
//
// The order matters. NFKC first, because it turns fullwidth and other
// compatibility forms into ordinary Latin, which is what makes a phrase written
// as fullwidth characters match. Confusable folding second, because NFKC does
// not touch Cyrillic lookalikes: they are different characters, not
// compatibility variants, and Unicode is right about that.
//
// Dropping invisible codepoints is what closes the one-character bypass. A
// single U+200B inside a word is deliberately not a structural finding, because
// one stray zero-width space is an import artifact rather than a payload (see
// minInvisibleRun). But it used to also split a phrase in half here, so
// "ignore all previou<U+200B>s instructions" came back clean from BOTH layers
// on one character. Neither decision was wrong alone; they failed to compose.
// Removing the codepoints at the point of comparison fixes the composition
// without weakening the structural threshold, because a value whose only
// anomaly is one invisible character still has nothing structural to report.
func normalizeForMatch(s string) string {
	folded := norm.NFKC.String(s)

	var b strings.Builder
	b.Grow(len(folded))
	lastSpace := false
	for _, r := range folded {
		if isInvisible(r) || isBidiOpen(r) || isBidiClose(r) {
			// Invisible to the agent reading the row, so invisible here too.
			continue
		}
		if latin, ok := confusableToLatin[r]; ok {
			r = latin
		}
		if unicode.IsSpace(r) {
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		lastSpace = false
		b.WriteRune(unicode.ToLower(r))
	}
	return strings.TrimSpace(b.String())
}

// confusableToLatin folds the Cyrillic and Greek letters that render as Latin.
//
// This is a hand-maintained table rather than a dependency on purpose. The two
// Go implementations of the Unicode confusables data are a 4-star repository and
// an untagged 2021 commit, and a security-relevant mapping that can be read in
// full in forty lines is worth more than either. The full UTS 39 table is much
// larger; this covers the letters that appear in the attacks.
//
// This table is deliberately LOOSER than isLatinLookalike in structural.go, and
// the two are not interchangeable. Folding alpha to a here costs nothing,
// because the result only decides whether a known phrase matches. Treating
// alpha as a Latin lookalike there would flag TNFα in a customer's assay table
// at high confidence. A layer that only produces a reason to look can afford to
// be generous; the layer meant to be acted on unattended cannot.
var confusableToLatin = map[rune]rune{
	// Cyrillic lowercase.
	'а': 'a', 'в': 'b', 'е': 'e', 'к': 'k', 'м': 'm',
	'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't',
	'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
	'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
	// Cyrillic uppercase.
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M',
	'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T',
	'У': 'Y', 'Х': 'X', 'І': 'I', 'Ј': 'J', 'Ѕ': 'S',
	// Greek lowercase.
	'α': 'a', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'ρ': 'p',
	'ν': 'v', 'υ': 'u', 'κ': 'k', 'τ': 't', 'χ': 'x',
	// Greek uppercase.
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H',
	'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
	'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	// Armenian. These are the substitutions the structural layer missed
	// entirely before it learned to count more than three script families.
	'օ': 'o', 'ո': 'n', 'ս': 's', 'ց': 'g', 'գ': 'q', 'ր': 'r',
}
