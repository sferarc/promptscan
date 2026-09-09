package promptscan

import (
	"strings"
	"testing"
)

// Finding.Evidence promises "the offending substring with invisible codepoints
// rendered visible", and the public API repeats that promise word for word in
// backend/openapi/schemas/text-scan.yaml. Every other detector keeps it by
// running its evidence through renderInvisible; the mixed-script detector
// returned the raw word.
//
// That was unreachable until the word stopped ending on a format codepoint. Now
// that it does not, a word carrying an invisible codepoint or a bidirectional
// override is exactly what the detector reports, so the raw bytes go into the
// evidence, out of the HTTP response, and into whatever reads it.
//
// A bidi override is the case that costs something. U+202E inside the reported
// word reorders every character after it in a terminal, a log line or a ticket,
// which is the trick the package exists to name and not something it should be
// handing to the reader unrendered.

func findingFor(t *testing.T, r Result, want Technique) Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.Technique == want {
			return f
		}
	}
	t.Fatalf("no %s finding, got %v", want, techniques(r))
	return Finding{}
}

func TestMixedScript_EvidenceRendersFormatCodepointsVisible(t *testing.T) {
	s := mustNew(t, Config{Structural: true})

	// The spoof from the split test, with the format codepoint between the
	// Cyrillic half and the Latin half so it lands inside the reported word.
	const spoof = "раypal"
	const at = len("ра")

	for _, r := range formatNeutralRunes(t) {
		value := spoof[:at] + string(r) + spoof[at:]
		got := s.Scan([]byte(value))
		f := findingFor(t, got, TechniqueMixedScript)

		if strings.ContainsRune(f.Evidence, r) {
			t.Errorf("U+%04X: evidence %q carries the codepoint unrendered", r, f.Evidence)
		}
		if strings.ContainsRune(f.Detail, r) {
			t.Errorf("U+%04X: detail %q carries the codepoint unrendered", r, f.Detail)
		}
		if want := renderInvisible(string(r)); !strings.Contains(f.Evidence, want) {
			t.Errorf("U+%04X: evidence %q does not name it as %q", r, f.Evidence, want)
		}
	}
}

// The ordinary case must not start reading like an escape sequence. A word with
// nothing invisible in it is reported exactly as it was stored.
func TestMixedScript_EvidenceLeavesAVisibleWordAlone(t *testing.T) {
	s := mustNew(t, Config{Structural: true})

	const spoof = "раypal"
	got := s.Scan([]byte(spoof))
	f := findingFor(t, got, TechniqueMixedScript)

	if f.Evidence != spoof {
		t.Errorf("evidence = %q, want %q", f.Evidence, spoof)
	}
	if !strings.Contains(f.Detail, spoof) {
		t.Errorf("detail = %q, want it to quote %q", f.Detail, spoof)
	}
}
