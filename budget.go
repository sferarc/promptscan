package promptscan

import "fmt"

// DefaultStatementMaxBytes is the budget for one Run when Budget.MaxBytes is
// zero.
//
// Sized from the measured cost of the structural layer on non-ASCII input,
// which is the column an integration has to be sized against: 3239 ns per 400
// byte value, so 4 MiB of scanned content is roughly ten thousand such values
// and roughly 34 ms of CPU added to one statement. That is affordable for an
// interactive result set, and it deliberately does not cover a bulk export,
// which is the case this budget exists to stop rather than to serve.
const DefaultStatementMaxBytes = 4 << 20

// Budget bounds the scanning done for one statement.
//
// Config.MaxBytes bounds one value and nothing bounds a result set, so a
// million row export pays the per-value cost a million times with no ceiling,
// no sampling and no lever an operator can pull. A scanner on a relay path
// needs a second limit, one that spans values, and this is it.
type Budget struct {
	// MaxBytes is how much value content the run will scan in total, counted
	// before the per-value cap is applied.
	//
	// Zero means DefaultStatementMaxBytes. Negative spends nothing and reports
	// every value unscannable saying so, because a budget somebody
	// misconfigured must not read as a result set nobody objected to.
	MaxBytes int
}

// RunStats is what a caller reports once per statement rather than once per
// row. A flagged value tends to recur across many rows of one result set, and
// an audit log that records the same budget overrun once per row is an audit
// log nobody reads.
type RunStats struct {
	// BytesScanned is how much of the budget was spent.
	BytesScanned int
	// ValuesScanned is how many values the detectors ran on, in whole or in
	// part.
	ValuesScanned int
	// ValuesUnscanned is how many values were refused outright because the
	// budget was already gone. Every one of them got VerdictUnscannable.
	ValuesUnscanned int
	// Exhausted reports whether any value was cut short or refused because the
	// budget ran out. It is the one bit worth putting in an audit event: it
	// says this result set was not fully scanned, so the absence of findings
	// covers only part of it.
	Exhausted bool
}

// Run is one statement's worth of scanning.
//
// Unlike Scanner it is stateful, because a budget that spans values is state,
// and it is therefore NOT safe for concurrent use. One Run belongs to one
// statement on one connection. The Scanner it came from is unchanged and stays
// safe to share, so a connection holds one scanner and takes a fresh Run per
// statement.
type Run struct {
	scanner *Scanner
	// budget is the resolved Budget.MaxBytes, kept so an exhausted run can say
	// what it was working with and can tell a spent budget from one that was
	// negative to begin with.
	budget    int
	remaining int
	stats     RunStats
}

// NewRun starts a statement-scoped run against this scanner.
//
// It never fails. A nil or unbuilt scanner produces a Run whose every value is
// unscannable, the same answer Scanner.Scan gives, rather than a nil Run that
// panics at the first row of a result set.
func (s *Scanner) NewRun(b Budget) *Run {
	budget := b.MaxBytes
	if budget == 0 {
		budget = DefaultStatementMaxBytes
	}
	remaining := max(budget, 0)
	return &Run{scanner: s, budget: budget, remaining: remaining}
}

// Scan inspects one value against the run's remaining budget.
//
// It follows Scanner.Scan in never returning an error and never reporting an
// unread value as clean. A value the budget cannot cover is VerdictUnscannable
// with a budget_exhausted finding, and a value it can cover only in part is
// scanned as far as the budget goes and reported the same way. What must not
// happen is a row silently skipped, which would reintroduce the bug this whole
// package is shaped against: absent coverage reading as an all-clear.
func (r *Run) Scan(value []byte) Result {
	if r == nil || r.scanner == nil || !r.scanner.built {
		return notBuiltResult()
	}
	if len(value) == 0 {
		r.stats.ValuesScanned++
		return Result{Verdict: VerdictClean}
	}
	if r.remaining <= 0 {
		r.stats.ValuesUnscanned++
		r.stats.Exhausted = true
		return Result{
			Verdict: VerdictUnscannable,
			Findings: []Finding{{
				Layer:      LayerStructural,
				Technique:  TechniqueBudgetExhausted,
				Confidence: ConfidenceMedium,
				Offset:     -1,
				Detail:     r.exhaustedDetail(len(value)),
			}},
		}
	}

	// The per-value cap and the budget are both ceilings and the lower one
	// binds. Which one it was decides how the value is reported, so a caller
	// reading the findings can tell an oversized value from a spent budget.
	limit := r.scanner.maxBytes
	cutByBudget := false
	if r.remaining < limit {
		limit = r.remaining
		cutByBudget = len(value) > limit
	}

	// Charge the limit rather than the bytes the rune boundary let us read.
	// They differ by up to three bytes, and charging the smaller one lets a
	// value whose first rune does not fit leave the budget where it was, so
	// every later value would scan nothing and the run would never finish
	// spending.
	spend := min(len(value), limit)
	r.remaining -= spend
	r.stats.BytesScanned += spend
	r.stats.ValuesScanned++
	if cutByBudget {
		r.stats.Exhausted = true
	}

	return r.scanner.scanWithin(value, limit, cutByBudget)
}

// Remaining is how much budget is left, in bytes.
func (r *Run) Remaining() int {
	if r == nil {
		return 0
	}
	return r.remaining
}

// Stats is the run's coverage so far, for the one audit event a statement
// should produce.
func (r *Run) Stats() RunStats {
	if r == nil {
		return RunStats{}
	}
	return r.stats
}

func (r *Run) exhaustedDetail(valueBytes int) string {
	if r.budget <= 0 {
		return fmt.Sprintf(
			"statement scan budget is %d bytes, so this %d byte value was not scanned",
			r.budget, valueBytes,
		)
	}
	return fmt.Sprintf(
		"statement scan budget of %d bytes is spent, so this %d byte value was not scanned",
		r.budget, valueBytes,
	)
}
