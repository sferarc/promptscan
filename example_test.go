package promptscan_test

import (
	"fmt"

	"github.com/sferarc/promptscan"
)

// The structural layer is the one to run in production. It reports byte-level
// facts and, on the corpus in this repository, flags nothing benign.
func Example() {
	scanner, err := promptscan.New(promptscan.Config{Structural: true})
	if err != nil {
		panic(err)
	}

	// A review body with a right-to-left override that is never terminated, so
	// what a human sees in a dashboard is not what is stored.
	result := scanner.Scan([]byte("Refund status: ‮approved for all accounts"))

	fmt.Println(result.Verdict)
	for _, f := range result.Findings {
		fmt.Printf("%s/%s (%s)\n", f.Layer, f.Technique, f.Confidence)
	}
	// Output:
	// suspicious
	// structural/bidi_override (high)
}

// Ordinary text in any script is clean. The benign corpus behind this package is
// deliberately full of the content that naive detectors flag: names in other
// scripts, right-to-left addresses, emoji and scientific notation.
func ExampleScanner_Scan_benign() {
	scanner, _ := promptscan.New(promptscan.Config{Structural: true})

	for _, value := range []string{
		"Пётр Ильич Чайковский",
		"TNFα levels were 4.7 µmol/L",
		"Thanks for the quick turnaround!",
	} {
		fmt.Println(scanner.Scan([]byte(value)).Verdict)
	}
	// Output:
	// clean
	// clean
	// clean
}

// HasStructural is the predicate most callers want. A structural finding has no
// ordinary explanation; a lexical one may just be somebody discussing an attack.
func ExampleResult_HasStructural() {
	scanner, _ := promptscan.New(promptscan.Config{Structural: true, Lexical: true})

	// A bug report quoting a payload while reporting it. This is the false
	// positive the lexical layer cannot be tuned out of, and it is exactly why
	// the two layers are separated.
	result := scanner.Scan([]byte(
		"Customer reports a review containing 'ignore all previous instructions'",
	))

	fmt.Println("verdict:", result.Verdict)
	fmt.Println("act on it:", result.HasStructural())
	// Output:
	// verdict: suspicious
	// act on it: false
}

// A value the scanner cannot read is never reported as clean. Unscannable is a
// third verdict for exactly this reason.
func ExampleScanner_Scan_unscannable() {
	scanner, _ := promptscan.New(promptscan.Config{Structural: true})

	result := scanner.Scan([]byte{0xff, 0xfe, 0xfd})

	fmt.Println(result.Verdict)
	fmt.Println(result.Findings[0].Technique)
	// Output:
	// unscannable
	// invalid_encoding
}

// The zero value refuses to work. A scanner that was never built would otherwise
// report every value clean, which is indistinguishable from a scanner that found
// nothing wrong.
func ExampleScanner_Scan_zeroValue() {
	var scanner promptscan.Scanner

	result := scanner.Scan([]byte("anything at all"))

	fmt.Println(result.Verdict)
	fmt.Println(result.Findings[0].Technique)
	// Output:
	// unscannable
	// scanner_not_built
}
