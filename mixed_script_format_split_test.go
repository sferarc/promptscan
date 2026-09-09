package promptscan

import (
	"testing"
)

// The structural layer scopes its mixed-script detector to a word, and a word
// used to end at the first rune that was not a letter, a digit or a mark. Every
// invisible formatting codepoint is none of those, so one of them dropped into
// the middle of a spoofed token split it into two single-script halves and the
// detector had nothing left to object to.
//
// That is the same composition failure the lexical layer already fixed in
// normalizeForMatch, in the layer whose findings are meant to be acted on
// unattended: "раypal" is reported at high confidence, and "ра<U+200B>ypal"
// came back clean, which Decide turns into allow.
//
// The threshold in detectInvisibleRun is not the thing to move. One stray
// invisible codepoint really is an import artifact rather than a payload, so a
// single one is correctly not a finding on its own. What it must not do is
// change the answer of a different detector.

// formatNeutralRunes is derived from the predicates rather than listed, so a
// codepoint added to isInvisible, isBidiOpen or isBidiClose later is covered by
// this test the day it is added.
func formatNeutralRunes(t *testing.T) []rune {
	t.Helper()
	var out []rune
	for r := rune(0); r <= 0x10FFFF; r++ {
		if isInvisible(r) || isBidiOpen(r) || isBidiClose(r) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		t.Fatal("no format-neutral codepoints found, so this test proves nothing")
	}
	return out
}

func TestMixedScript_FormatCodepointDoesNotSplitAWord(t *testing.T) {
	s := mustNew(t, Config{Structural: true})

	// The control: the spoof with nothing hidden in it. Cyrillic "ра" in front
	// of Latin "ypal", one token, no honest reading.
	const spoof = "раypal"
	if got := s.Scan([]byte(spoof)); got.Verdict != VerdictSuspicious {
		t.Fatalf("control %q: verdict = %q, want %q (the rest of this test means nothing without it)",
			spoof, got.Verdict, VerdictSuspicious)
	}

	// Between the Cyrillic half and the Latin half, which is where the split
	// would happen.
	const at = len("ра")
	for _, r := range formatNeutralRunes(t) {
		value := spoof[:at] + string(r) + spoof[at:]
		got := s.Scan([]byte(value))
		if got.Verdict != VerdictSuspicious {
			t.Errorf("U+%04X inside the word: verdict = %q, want %q", r, got.Verdict, VerdictSuspicious)
			continue
		}
		if !hasTechnique(got, TechniqueMixedScript) {
			t.Errorf("U+%04X inside the word: no %s finding, got %v",
				r, TechniqueMixedScript, techniques(got))
		}
	}
}

// A balanced bidi pair is the same bypass with two codepoints instead of one,
// and it is the one detectUnbalancedBidi is deliberately blind to: balanced
// marks are how right-to-left text works, so their presence proves nothing.
func TestMixedScript_BalancedBidiPairDoesNotSplitAWord(t *testing.T) {
	s := mustNew(t, Config{Structural: true})

	const value = "ра‪ypal‬"
	got := s.Scan([]byte(value))
	if got.Verdict != VerdictSuspicious {
		t.Fatalf("verdict = %q, want %q", got.Verdict, VerdictSuspicious)
	}
	if !hasTechnique(got, TechniqueMixedScript) {
		t.Fatalf("no %s finding, got %v", TechniqueMixedScript, techniques(got))
	}
}

// Joining across a format codepoint must not start flagging ordinary content.
// A soft hyphen is what a word processor leaves in a hyphenated word, and the
// value it produces is one word in the script it already was.
func TestMixedScript_FormatCodepointDoesNotManufactureAMixture(t *testing.T) {
	s := mustNew(t, Config{Structural: true})

	for _, value := range []string{
		"co­operate",     // soft hyphen inside an English word
		"Пётр­Ильич",     // soft hyphen inside a Cyrillic name
		"ビタミン​C",         // Han/Kana beside Latin, not a confusable pair
		"TNFα and IL2Rα", // lowercase Greek, which is how science is written
		"hello​​",        // an invisible run alone is not a mixture
	} {
		got := s.Scan([]byte(value))
		if hasTechnique(got, TechniqueMixedScript) {
			t.Errorf("%q: reported %s, want no mixture finding (detail %q)",
				value, TechniqueMixedScript, findingDetail(got, TechniqueMixedScript))
		}
	}
}

func findingDetail(r Result, want Technique) string {
	for _, f := range r.Findings {
		if f.Technique == want {
			return f.Detail
		}
	}
	return ""
}
