package promptscan

import (
	"strings"
	"testing"
)

// Benchmarks exist to answer one question the wire-path design note has to
// answer: what does scanning cost per column value, given that the relay path
// touches every value of every row.
//
// The sizes are chosen to match what a text column actually holds. A name or a
// status is tens of bytes, a description is hundreds, a support ticket body or
// a review is a few kilobytes.
//
// # Every input here used to be ASCII, which measured the wrong thing
//
// scanStructural returns after one linear pass when a value is pure ASCII,
// because every technique it detects requires a non-ASCII codepoint. That fast
// path is real and it is worth having. It also meant the published cost of the
// structural layer was the cost of isASCII: not one of the four detectors ran
// in any benchmark, and the numbers in the package documentation and the design
// note described a function that only decides whether to start work.
//
// The gap is 52x on the same 400 byte value, and one accented character is
// enough to cross it. So the sizes below are run twice, once ASCII and once
// not, and the non-ASCII row is the one an integration decision has to be made
// against, because "the customer writes English" is not an assumption this
// product gets to make.
var benchValues = map[string]string{
	"short_40b":  "Delivered to the front desk on Tuesday.",
	"medium_400": strings.Repeat("The package arrived on time and in good condition. ", 8),
	"long_4kb":   strings.Repeat("Customer wrote in about a billing discrepancy on the March invoice. ", 60),
}

// benchValuesNonASCII are the same sizes in ordinary French and Russian, so
// they carry accented and Cyrillic letters and cannot take the fast path. There
// is nothing anomalous in any of them and every detector runs to completion,
// which is exactly the point: this is the cost of a clean non-English value.
var benchValuesNonASCII = map[string]string{
	"short_40b":  "Livré à la réception mardi après-midi.",
	"medium_400": strings.Repeat("Le paquet est arrivé à temps et en bon état. ", 9),
	"long_4kb":   strings.Repeat("Клиент написал о расхождении в счёте за март. ", 49),
}

func BenchmarkScanStructural(b *testing.B) {
	s, err := New(Config{Structural: true})
	if err != nil {
		b.Fatal(err)
	}
	for name, v := range benchValues {
		value := []byte(v)
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(value)))
			b.ReportAllocs()
			for b.Loop() {
				s.Scan(value)
			}
		})
	}
}

// BenchmarkScanStructuralNonASCII is the number that decides whether this layer
// can sit on the relay path. Its ASCII twin above is not.
func BenchmarkScanStructuralNonASCII(b *testing.B) {
	s, err := New(Config{Structural: true})
	if err != nil {
		b.Fatal(err)
	}
	for name, v := range benchValuesNonASCII {
		value := []byte(v)
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(value)))
			b.ReportAllocs()
			for b.Loop() {
				s.Scan(value)
			}
		})
	}
}

func BenchmarkScanBothLayers(b *testing.B) {
	s, err := New(Config{Structural: true, Lexical: true})
	if err != nil {
		b.Fatal(err)
	}
	for name, v := range benchValues {
		value := []byte(v)
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(value)))
			b.ReportAllocs()
			for b.Loop() {
				s.Scan(value)
			}
		})
	}
}

func BenchmarkScanBothLayersNonASCII(b *testing.B) {
	s, err := New(Config{Structural: true, Lexical: true})
	if err != nil {
		b.Fatal(err)
	}
	for name, v := range benchValuesNonASCII {
		value := []byte(v)
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(value)))
			b.ReportAllocs()
			for b.Loop() {
				s.Scan(value)
			}
		})
	}
}

// BenchmarkScanASCIIFastPath measures the case that dominates English-language
// traffic: a short ASCII value with nothing wrong with it.
func BenchmarkScanASCIIFastPath(b *testing.B) {
	s, err := New(Config{Structural: true})
	if err != nil {
		b.Fatal(err)
	}
	value := []byte("shipped")
	b.SetBytes(int64(len(value)))
	b.ReportAllocs()
	for b.Loop() {
		s.Scan(value)
	}
}

// BenchmarkScanAtCap measures a value at the default scan cap, which is the
// worst case a single column value can cost. The tag_prefix variant is the one
// an attacker picks: before the prefix gate was widened from two bytes to
// three, a single Variation Selector Supplement codepoint (ordinary in
// Japanese) forced a full decode into a []rune plus a []int of byte offsets,
// 1.18MB allocated to then find nothing at all.
func BenchmarkScanAtCap(b *testing.B) {
	s, err := New(Config{Structural: true})
	if err != nil {
		b.Fatal(err)
	}
	cases := map[string]string{
		"ascii":       strings.Repeat("a", DefaultMaxBytes),
		"non_ascii":   strings.Repeat("é", DefaultMaxBytes/2),
		"tag_prefix":  "\U000E0100" + strings.Repeat("a", DefaultMaxBytes-4),
		"tag_payload": "\U000E0041" + strings.Repeat("a", DefaultMaxBytes-4),
	}
	for name, v := range cases {
		value := []byte(v)
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(value)))
			b.ReportAllocs()
			for b.Loop() {
				s.Scan(value)
			}
		})
	}
}
