package promptscan

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// Verdict is the top-level outcome of scanning one value.
type Verdict string

const (
	// VerdictClean means the scanner read the whole value and objected to
	// nothing.
	VerdictClean Verdict = "clean"
	// VerdictSuspicious means at least one detector produced a finding.
	VerdictSuspicious Verdict = "suspicious"
	// VerdictUnscannable means the scanner could not judge the value, so the
	// absence of findings says nothing. Callers must not treat it as Clean.
	VerdictUnscannable Verdict = "unscannable"
)

// Layer is which family of detector produced a finding. Callers are expected to
// treat the two differently: structural findings are byte facts, lexical
// findings are a guess about wording.
type Layer string

const (
	// LayerStructural covers detectors that read codepoints and scripts. These
	// have no legitimate explanation in ordinary database text.
	LayerStructural Layer = "structural"
	// LayerLexical covers phrase matching. It is the layer that produces false
	// positives, because a bug report quoting an attack contains the attack.
	LayerLexical Layer = "lexical"
)

// Technique names what was found.
type Technique string

const (
	// TechniqueInvisibleRun is a run of zero-width or invisible codepoints,
	// which is how instructions are hidden from a human reviewing the row.
	TechniqueInvisibleRun Technique = "invisible_run"
	// TechniqueTagSmuggling is Unicode Tag codepoints (U+E0000 to U+E007F),
	// which map one to one onto ASCII and render as nothing at all.
	TechniqueTagSmuggling Technique = "tag_smuggling"
	// TechniqueBidiOverride is an unterminated bidirectional override, which
	// makes displayed text differ from stored text.
	TechniqueBidiOverride Technique = "bidi_override"
	// TechniqueMixedScript is a single word mixing scripts that render alike,
	// such as Latin with Cyrillic lookalikes.
	TechniqueMixedScript Technique = "mixed_script"
	// TechniqueInstructionPhrase is wording associated with instruction
	// override. Reported at low confidence on its own.
	TechniqueInstructionPhrase Technique = "instruction_phrase"
	// TechniqueInvalidEncoding is a value that is not valid UTF-8, so the
	// detectors below could not read it.
	TechniqueInvalidEncoding Technique = "invalid_encoding"
	// TechniqueTruncated is a value longer than the scan cap, so only its
	// prefix was read. It is its own technique rather than a reuse of
	// invalid_encoding, because a caller filtering on technique would
	// otherwise see a perfectly valid 100KB value reported as malformed.
	TechniqueTruncated Technique = "truncated"
	// TechniqueBudgetExhausted is a value the statement budget did not cover,
	// so it was read in part or not at all. It is distinct from truncated
	// because the two say different things about the run: truncated is one
	// oversized value, and this one means the result set outgrew what the
	// caller was willing to spend and every value after it is in the same
	// state. Reported at medium confidence when nothing was read and low when
	// a prefix was, matching invalid_encoding and truncated respectively.
	TechniqueBudgetExhausted Technique = "budget_exhausted"
	// TechniqueScannerNotBuilt is the zero-value scanner guard. It exists so a
	// caller that skipped New gets told, rather than getting silence.
	TechniqueScannerNotBuilt Technique = "scanner_not_built"
)

// Confidence is deliberately an ordered enum rather than a score. There is no
// arithmetic on it, so there is no threshold to tune and no NaN to compare
// false against every guard.
type Confidence string

const (
	// ConfidenceLow means the finding is worth recording and is not worth
	// acting on alone.
	ConfidenceLow Confidence = "low"
	// ConfidenceMedium means the finding has no ordinary explanation but has a
	// plausible accidental one.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceHigh means the finding has no accidental explanation the author
	// of this package could construct.
	ConfidenceHigh Confidence = "high"
)

// Rank orders confidence so callers can filter without comparing strings.
// Higher is more confident. An unrecognized value ranks 0, which is the
// conservative direction for a filter written as "at least medium".
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceLow:
		return 1
	case ConfidenceMedium:
		return 2
	case ConfidenceHigh:
		return 3
	default:
		return 0
	}
}

// Finding is one detection, with the bytes that caused it.
type Finding struct {
	Layer      Layer
	Technique  Technique
	Confidence Confidence
	// Offset is the byte offset into the scanned value where the evidence
	// starts, or -1 when the finding is about the value as a whole.
	Offset int
	// Evidence is the offending substring with invisible codepoints rendered
	// visible, truncated. It is safe to log and safe to show in a terminal.
	Evidence string
	// Detail explains the finding in one line.
	Detail string
}

// Result is the outcome of one scan.
type Result struct {
	Verdict  Verdict
	Findings []Finding
}

// Highest returns the strongest confidence among the findings, and false when
// there are none.
func (r Result) Highest() (Confidence, bool) {
	best := Confidence("")
	found := false
	for _, f := range r.Findings {
		if f.Confidence.Rank() > best.Rank() {
			best = f.Confidence
			found = true
		}
	}
	return best, found
}

// HasStructural reports whether any finding came from the structural layer.
// This is the predicate most callers actually want, because the structural
// layer is the one whose findings have no ordinary explanation.
func (r Result) HasStructural() bool {
	for _, f := range r.Findings {
		if f.Layer == LayerStructural {
			return true
		}
	}
	return false
}

// Config selects which detectors run. There is no useful zero value on purpose:
// New refuses a Config that enables nothing, because a scanner that cannot find
// anything reports clean forever and looks exactly like a scanner that found
// nothing wrong.
type Config struct {
	// Structural enables the byte-level and script-level detectors.
	Structural bool
	// Lexical enables phrase matching. Off is a reasonable production choice;
	// see the package documentation on what it costs.
	Lexical bool
	// Phrases overrides the built-in phrase set. Ignored when Lexical is false.
	// Every entry is lowercased at build time; an empty or whitespace-only
	// entry is refused rather than silently dropped, because a phrase list that
	// quietly shrank is a scanner that quietly stopped looking.
	Phrases []string
	// MaxBytes caps how much of a value is scanned. Values longer than this are
	// scanned up to the cap and the result carries a truncation finding, so a
	// long value is never silently half-checked. Zero means DefaultMaxBytes.
	MaxBytes int
}

// DefaultMaxBytes is the scan cap when Config.MaxBytes is zero. A text column
// can hold a gigabyte, and scanning one on the relay path would be a denial of
// service against the connection it is trying to protect.
const DefaultMaxBytes = 64 * 1024

// ErrNoDetectors is returned by New when the Config enables no detector.
var ErrNoDetectors = errors.New("promptscan: config enables no detector, which would report every value clean")

// Scanner inspects values. It is safe for concurrent use once built, and it
// holds no per-scan state.
type Scanner struct {
	// built is what makes the zero value refuse to work. It is set only by New.
	built      bool
	structural bool
	lexical    bool
	phrases    *phraseMatcher
	maxBytes   int
}

// New builds a Scanner, or returns an error explaining why the configuration
// would produce a scanner that cannot object to anything.
func New(cfg Config) (*Scanner, error) {
	if !cfg.Structural && !cfg.Lexical {
		return nil, ErrNoDetectors
	}
	maxBytes := cfg.MaxBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxBytes < 0 {
		return nil, fmt.Errorf("promptscan: MaxBytes is %d, want a positive byte count", maxBytes)
	}

	s := &Scanner{
		built:      true,
		structural: cfg.Structural,
		lexical:    cfg.Lexical,
		maxBytes:   maxBytes,
	}

	if cfg.Lexical {
		phrases := cfg.Phrases
		if phrases == nil {
			phrases = DefaultPhrases()
		}
		m, err := newPhraseMatcher(phrases)
		if err != nil {
			return nil, err
		}
		s.phrases = m
	}
	return s, nil
}

// Scan inspects one value and reports what it found.
//
// It never returns an error. A value it cannot read produces VerdictUnscannable
// with a finding naming the reason, because a caller on a relay path needs a
// verdict, and an error return there invites the caller to ignore it and carry
// on with a zero Result, which would read as clean.
func (s *Scanner) Scan(value []byte) Result {
	if s == nil || !s.built {
		return notBuiltResult()
	}
	if len(value) == 0 {
		return Result{Verdict: VerdictClean}
	}
	return s.scanWithin(value, s.maxBytes, false)
}

// notBuiltResult is the lattice-bottom guard. A caller that skipped New gets
// told so rather than getting silence.
func notBuiltResult() Result {
	return Result{
		Verdict: VerdictUnscannable,
		Findings: []Finding{{
			Layer:      LayerStructural,
			Technique:  TechniqueScannerNotBuilt,
			Confidence: ConfidenceHigh,
			Offset:     -1,
			Detail:     "scanner was not built by New, so no detector ran",
		}},
	}
}

// scanWithin scans at most limit bytes of value. cutByBudget selects which
// technique reports a value the scan did not reach the end of: an oversized
// value and a spent statement budget are different facts about coverage, and a
// caller filtering on technique has to be able to tell them apart.
//
// The caller has already ruled out an unbuilt scanner and an empty value.
func (s *Scanner) scanWithin(value []byte, limit int, cutByBudget bool) Result {
	scanned := value
	truncated := false
	if len(scanned) > limit {
		scanned = truncateAtRuneBoundary(scanned, limit)
		truncated = true
	}

	var findings []Finding
	if !utf8.Valid(scanned) {
		// Not clean and not suspicious: unreadable. The detectors below all
		// decode runes, so running them on invalid UTF-8 would silently skip
		// whatever the invalid bytes were hiding.
		findings = append(findings, Finding{
			Layer:      LayerStructural,
			Technique:  TechniqueInvalidEncoding,
			Confidence: ConfidenceMedium,
			Offset:     -1,
			Detail:     "value is not valid UTF-8, so the content detectors could not read it",
		})
		return Result{Verdict: VerdictUnscannable, Findings: findings}
	}

	if s.structural {
		findings = append(findings, scanStructural(scanned)...)
	}
	if s.lexical && s.phrases != nil {
		findings = append(findings, s.phrases.scan(scanned)...)
	}

	verdict := VerdictClean
	if len(findings) > 0 {
		verdict = VerdictSuspicious
	}
	if truncated {
		// A value scanned only in part cannot be called clean. If something was
		// found in the prefix the verdict is already suspicious; if nothing
		// was, the honest answer is that we did not look at all of it.
		if verdict == VerdictClean {
			verdict = VerdictUnscannable
		}
		technique := TechniqueTruncated
		detail := fmt.Sprintf(
			"value is %d bytes and only the first %d were scanned",
			len(value), len(scanned),
		)
		if cutByBudget {
			technique = TechniqueBudgetExhausted
			detail = fmt.Sprintf(
				"statement scan budget ran out %d bytes into a %d byte value",
				len(scanned), len(value),
			)
		}
		findings = append(findings, Finding{
			Layer:      LayerStructural,
			Technique:  technique,
			Confidence: ConfidenceLow,
			// Where the scan actually stopped, not where the cap sits. The two
			// differ by up to three bytes whenever the cap lands mid-rune.
			Offset: len(scanned),
			Detail: detail,
		})
	}

	return Result{Verdict: verdict, Findings: findings}
}

// truncateAtRuneBoundary cuts b to at most max bytes without splitting a rune,
// so the truncated tail cannot be misread as invalid UTF-8.
func truncateAtRuneBoundary(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return b[:cut]
}
