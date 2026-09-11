// Deny-by-default is Cedar's native semantics — if no `permit` matches a
// request, the decision is Deny. An unconditional `forbid` here would
// override every `permit` (forbid always wins) and make the policy set
// incapable of ever allowing anything. Exceptions-as-`forbid` belong in a
// later file (e.g. 90-step-up.cedar) and should carry conditions that narrow
// them to the unsafe case. This file is intentionally empty.
