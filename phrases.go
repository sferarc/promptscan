package promptscan

// The built-in phrase set.
//
// Every entry earns its place by being a phrase that addresses a reader as an
// instruction-following system. That is the only thing they have in common, and
// it is deliberately narrow. Phrases that merely sound security-adjacent
// ("password", "api key", "confidential") are not here: a database is full of
// rows that legitimately discuss those, and adding them would flag a support
// queue on its first scan.
//
// The set is short on purpose. Aho-Corasick makes the length free at runtime,
// so shortness is not an optimization: it is a statement that each phrase was
// argued for individually. A caller that wants more can pass Config.Phrases.
//
// # Nine phrases were removed after they were measured against ordinary text
//
// The first version of this list was argued for but never tested against
// content that was neither an attack nor a discussion of one. Every entry below
// was flagged by a plausible benign row, and the recall they were carrying was
// not worth the rows they would have flagged:
//
//   - "you are now": "You are now subscribed", "You are now logged out". This
//     is ordinary English, not writing about injection.
//   - "system:" and "assistant:": a diagnostics field reads "System: macOS
//     15.2"; a contact record reads "Assistant: Maria Gonzalez". Far worse,
//     the single most likely table in an AI-agent customer's database is a
//     store of LLM chat transcripts, where both appear in essentially every
//     row. A phrase that flags every row of the most likely table is not a
//     signal. The narrower framings that survive ("[system]", "<|system|>",
//     "<|im_start|>", "begin system message") do not have that problem.
//   - "drop table", "grant all privileges", "exfiltrate": none of these
//     addresses a reader as an instruction-following system, so all three
//     violated this file's own stated rule. They fire on migration logs, bug
//     reports, runbooks, database documentation and any security team's
//     knowledge base, and on this product's own audit records.
//   - "send the results to": "Please send the results to the lab by Friday."
//   - "do not mention this": "Do not mention this to the client until Monday."
//   - "admin override": ordinary on-call and ops text.
//
// Removing them costs one hostile corpus case, role_injection, which was
// carried entirely by "system:" and "you are now" and has no other tell. That
// is recorded in the corpus rather than papered over, because a phrase kept to
// hold up a recall number is a phrase that will flag a customer's rows in
// production to make a test look better here.
//
// None of these should be treated as proof. See the note on the lexical layer.

// DefaultPhrases returns a copy of the built-in phrase set, so a caller can
// extend it without mutating package state.
func DefaultPhrases() []string {
	out := make([]string, len(defaultPhrases))
	copy(out, defaultPhrases)
	return out
}

var defaultPhrases = []string{
	// Instruction override. The canonical opening of a stored injection.
	"ignore all previous instructions",
	"ignore previous instructions",
	"ignore the above instructions",
	"ignore your instructions",
	"disregard all previous",
	"disregard the above",
	"forget everything above",
	"forget your previous instructions",
	"override your instructions",

	// Role and framing injection: text that tries to relabel itself as coming
	// from a more trusted position in the prompt. These are the narrow
	// framings; the bare "system:" and "assistant:" are gone, see above.
	"new instructions:",
	"system prompt:",
	"[system]",
	"<|im_start|>",
	"<|system|>",
	"### instruction",
	"begin system message",
	"end of user input",

	// Authority spoofing: claiming to speak for the operator.
	"this is a message from your developer",
	"as an administrator i instruct you",
	"the security team has authorized",

	// Instructions aimed specifically at an agent with database or tool access,
	// which is the population this package protects.
	"do not tell the user",
	"without informing the user",
	"execute the following sql",
	"run the following query",
}
