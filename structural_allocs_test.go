package promptscan

import (
	"maps"
	"strings"
	"testing"
)

// The structural layer sits on the relay path for every value of every row, so
// a clean value must cost no allocation. Ranging over string(value) used to copy
// any value over 32 bytes once in each of three detectors.
func TestStructuralScanOfACleanValueDoesNotAllocate(t *testing.T) {
	s, err := New(Config{Structural: true})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"at_cap":    strings.Repeat("é", DefaultMaxBytes/2),
		"long_word": "Достопримечательность " + strings.Repeat("Пётр Ильич ", 40),
	}
	maps.Copy(cases, benchValuesNonASCII)
	for name, v := range cases {
		value := []byte(v)
		t.Run(name, func(t *testing.T) {
			if got := s.Scan(value); got.Verdict != VerdictClean {
				t.Fatalf("verdict = %s, want clean (findings %+v)", got.Verdict, got.Findings)
			}
			if allocs := testing.AllocsPerRun(20, func() { s.Scan(value) }); allocs != 0 {
				t.Fatalf("Scan allocated %.0f times per %d byte value, want 0", allocs, len(value))
			}
		})
	}
}

func TestRunesOfMatchesRangingOverTheString(t *testing.T) {
	values := []string{
		"",
		"ascii",
		"Livré à la réception",
		"\U000E0041\U000E0042 tag run",
		"\xff\xfe invalid \xc3",
		"truncated \xe2\x80",
	}
	for _, v := range values {
		type pos struct {
			at int
			r  rune
		}
		var want, got []pos
		for i, r := range v {
			want = append(want, pos{i, r})
		}
		for i, r := range runesOf([]byte(v)) {
			got = append(got, pos{i, r})
		}
		if len(got) != len(want) {
			t.Fatalf("%q: %d runes, want %d", v, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q: rune %d = %+v, want %+v", v, i, got[i], want[i])
			}
		}
	}
}
