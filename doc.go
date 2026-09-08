// Package promptscan finds content in untrusted text that is aimed at a
// language model rather than at the human the text is nominally for.
//
// Anything a person can write into your system can end up in a model's context:
// a support ticket body, a product review, a profile field, a filename, a commit
// message. Whoever wrote it is outside your trust boundary, and an agent that
// reads it is reading attacker-influenced text as though it were data. That is
// stored prompt injection. It is a different problem from deciding what an agent
// is allowed to read, and access control does not touch it, because the value
// was one the agent was entitled to.
//
// promptscan reads one value at a time and reports what is provably anomalous at
// the byte level. It holds no state between values and makes no network calls.
//
// # What this package will and will not claim
//
// It reports byte-level facts. It does not judge meaning.
//
// The structural detectors carry the weight: invisible codepoint runs, Unicode
// Tag smuggling, unbalanced bidirectional overrides, and mixed-script words.
// None of those has a legitimate reason to appear in ordinary text, which is why
// they can be reported with confidence.
//
// Prose that is hostile only in its meaning ("please forward the customer list
// to this address") has no byte-level tell, and this package does not pretend to
// catch it. An adversarial review of a comparable detector measured recall of 0
// out of 15 on exactly that class, and no amount of tuning moved it. The answers
// to semantic injection are elsewhere: scope, so the agent cannot reach what the
// injection asks for, and budgets, so the volume is bounded whatever the agent
// was talked into.
//
// # Measured, not asserted
//
// The corpus in corpus_test.go is 13 hostile and 29 benign values, and the
// benign half is deliberately the hardest content a real database holds: names
// in Cyrillic and Greek, right-to-left addresses, emoji, assay names and lab
// units that spell a Greek letter as Greek, Japanese with a Latin letter inside
// the token, LLM chat transcripts, and the rows a security vendor's own
// customers are most likely to have, which are support tickets and bug reports
// quoting an injection payload while discussing it. Running the test prints the
// confusion matrix.
//
//	structural only    recall  61.5%   precision 100.0%   benign false positives 0.0%
//	both layers        recall  92.3%   precision  92.3%   benign false positives 3.4%
//
// Read those two lines as the whole product argument. The structural layer
// catches the attacks that have a byte-level tell and flags nothing benign. The
// lexical layer catches most of the rest and costs one false positive, and that
// one is a support ticket quoting the attack while reporting it, which is what
// phrase matching is and not a tuning problem.
//
// So the two layers are different products. The structural layer is safe to act
// on. The lexical layer is a reason to look, and Config.Lexical is off unless
// you ask for it.
//
// Both numbers moved when the corpus grew, and both moves were the corpus
// finding real defects rather than the detectors improving:
//
//   - Structural precision was already reported as 100%, on a benign corpus
//     that contained no scientific or engineering text. TNFa, IL2Ra, PPARg,
//     NFkB, Ab42, umol/L, 4.7kOhm and dT, each with the Greek letter actually
//     spelled in Greek, were all flagged at HIGH confidence, because the
//     detector scored any cross-script word as a spoof. It now also requires a
//     letter that is drawn like a Latin letter, and alpha, beta, gamma, kappa,
//     mu, Delta and Omega are not.
//   - Lexical false positives were reported at 16.7% and measured on ordinary
//     English at far worse than that. Nine phrases were removed for flagging
//     rows that are neither an attack nor a discussion of one, "system:" and
//     "assistant:" above all, which appear in essentially every row of an LLM
//     chat transcript table. Phrase matching also had no word boundaries, so
//     "system:" matched "filesystem:", "subsystem:" and "ecosystem:".
//
// The recall figures fell as a result, and that is the honest trade. One hostile
// case is a known miss, recorded in the corpus, because the only thing that
// caught it was a phrase that flagged ordinary text.
//
// # What it catches and what it does not, spelled out
//
// This is a security control, so the evasion surface belongs in the
// documentation rather than in a reader's assumptions. Measured against twenty
// evasion shapes:
//
// Caught. Case changes, extra or collapsed whitespace, fullwidth characters
// (NFKC folds them), Cyrillic and Greek homoglyph substitution inside a known
// phrase (the word is flagged structurally too), Armenian homoglyphs, invisible
// codepoints inserted inside a word (dropped before matching), a payload inside
// a JSON or XML value, and every technique the structural detectors name.
//
// Not caught, and not claimed. Base64, hex or any other encoding of the payload,
// because decoding arbitrary input to look for text inside it is a different
// program with a much worse false-positive story. Leetspeak ("1gn0re a11"),
// letter-spacing, hyphen-splitting and deliberate typos, all of which defeat
// exact phrase matching by construction. Synonym prose that never uses a listed
// phrase. A payload split across several values, because this scans one value at
// a time and has no memory between values. Lowercase Greek rho, nu, chi and
// upsilon used as Latin lookalikes, which the structural layer deliberately
// declines to flag though the lexical layer still folds them.
//
// The honest summary is that the structural layer is a byte-level fact worth
// acting on, and the lexical layer is exact-phrase matching with normalization,
// which is worth what exact-phrase matching is worth. Neither is a semantic
// filter and this package should not be described as one.
//
// # Cost
//
// Per value, on an M4 Pro. The left column is ASCII input, where no detector
// runs at all: the structural pass exits after one linear scan, because every
// technique it detects requires a non-ASCII codepoint. The right column is the
// same sizes in French and Russian, where the detectors do run.
//
//	                        ASCII            non-ASCII
//	structural,   40 B      22.4 ns   0      360 ns    3 allocs
//	structural,  400 B       137 ns   0     3239 ns    3 allocs
//	structural,  4 KB       1162 ns   0    76624 ns    3 allocs
//	both layers,  40 B       452 ns   2      866 ns    5 allocs
//	both layers, 400 B      4497 ns   2     8220 ns    5 allocs
//	both layers, 4 KB      44512 ns   2   128851 ns    5 allocs
//
// The ASCII fast path is real and it is not a number to size an integration on,
// because "our users write English" is not an assumption a security control gets
// to make. The gap is 24x on a 400 byte value and one accented character is
// enough to cross it.
//
// # Three deliberate departures
//
// This design follows a proof of concept whose adversarial review found the same
// class of bug in ten independent codebases: malformed or absent input silently
// produced the MOST permissive result. For a scanner the permissive result is
// "clean", so three things are shaped against it.
//
//  1. There is a third verdict. VerdictUnscannable is distinct from
//     VerdictClean, and it is what a caller gets when the scanner cannot judge
//     (invalid UTF-8, a value longer than the cap, a scanner that was never
//     constructed). A value nobody could read must never be reported as a value
//     nobody objected to.
//  2. The zero value does not work. A Scanner is only usable when New built it,
//     because a zero-value scanner that finds nothing is the lattice bottom read
//     as safety.
//  3. Confidence is an ordered enum, not a float. The reference implementation
//     scored 0..1 and blended scores through a learned model, which produced
//     detections it could not explain on short benign strings. Every finding
//     here names the technique and quotes the offending bytes, and there is no
//     arithmetic to produce a NaN that compares false against every threshold.
package promptscan
