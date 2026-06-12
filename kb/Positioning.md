---
tags: [positioning, pitch, cedar, formal-evidence]
source: llm
date: 2026-06-12
---
# Positioning

Why Arbiter exists, why it plays well with LLMs, and what Cedar plus SMT
buys us. Companion pitches live in the Ferrox and Soter knowledge bases; this
note is the Arbiter chapter of the same story.

## Elevator Pitch

Arbiter is the **authorization conscience of the Converge platform**: a
Cedar-backed policy extension that answers one narrow, high-stakes question —
*should this proposed action, flow transition, delegation, budget spend, or
data movement be allowed under policy, right now?*

It keeps policy evaluation, delegation verification (Ed25519-signed tokens),
and a family of reusable gates (policy, flow, rate-limit, budget, approval,
data-classification, compliance, HITL) outside the Converge kernel, so policy
participates as a first-class suggestor without turning the platform into a
policy engine.

It matters because agentic systems do not fail at *capability* — they fail
at *boundaries*, and Arbiter is where the boundaries live, with provenance
attached to every decision.

## Why It Plays Well With LLMs

An LLM's judgment is probabilistic and persuadable; authorization must be
neither. Arbiter gives an agentic system a **deterministic, auditable,
prompt-injection-immune veto** — the LLM proposes, Cedar disposes.

- The contract is agent-shaped: typed request in,
  `Promote` / `Escalate` / `Reject` out.
- HITL escalation is policy-derived, not heuristic: a denial becomes
  `Escalate` *only if Cedar itself confirms that the same request with
  `human_approval_present = true` would pass* — so the agent never bothers a
  human with an approval that could not change the outcome.
- Decisions carry execution identity and provenance, so an LLM can *explain*
  why it was blocked, in language, from structured evidence.

## What It Solves Better Than Anything Else

Arbiter's unmatched niche is **policy assurance that scales from runtime
decisions to mathematical evidence in one stack**. Most authorization layers
can tell you what happened on *this* request; Arbiter can also answer the
universally-quantified question: *can any modeled request exist that violates
this invariant?*

The assurance lane:

```text
Gherkin invariant
  -> review fixture matrix for model adequacy
  -> Cedar policy and schema validation
  -> Cedar runtime regression test
  -> symbolic compilation (cedar-policy-symcc) into SMT
  -> CVC5 solver execution
  -> counterexample or no-violation report
  -> hash-pinned (policy, schema, query, Cedar version) Searched evidence
     into the Converge promotion path
```

The worked exemplar — `ExpenseNonFinanceHighValueCommitDenied` — proves that
no non-finance principal can commit a high-value expense *even with every
approval gate satisfied*, not by testing cases but by exhausting the model.

Key algorithms: **Cedar's decidable policy evaluation and schema
validation**, **symbolic compilation to SMT**, **CDCL(T)/DPLL(T) SMT
solving** via CVC5 (Z3 planned), and **Ed25519** signature verification for
delegation chains.

## Cedar, SMT, And The USPs

**Cedar** (AWS's open-source authorization language, here on the 4.10 line)
was the right bet for three reasons:

1. It is *deliberately not Turing-complete* — no loops, no recursion — so
   every evaluation terminates and the language is **decidable**, which is
   precisely what makes symbolic analysis possible at all.
2. It is *formally specified*: upstream `cedar-spec` models its semantics in
   Lean, with the production evaluator differentially tested against the
   proof model.
3. It is fast enough to sit in the hot path of every agent action.

That decidability is the bridge to **SMT**: SymCC compiles real Cedar
policies — not hand-coded abstractions — into SMT assertions a solver can
exhaust, and the Soter CVC5 bridge proves the generated SMT is tied to
Arbiter's actual policy model.

The evidence discipline is itself a USP: runtime decisions are `Decided`,
solver results are `Searched`, and `Verified` is reserved for future checked
Lean artifacts; analysis produces *evidence for* promotion, never promotion
itself. See [[Architecture/Cedar Analytics and Formal Evidence]].

Summed up, the USPs:

- One policy text serving both runtime enforcement and offline proof-grade
  analysis.
- Counterexamples instead of test-coverage hope.
- Honest evidence tiers with cryptographic provenance.
- HITL escalation that is policy-derived rather than heuristic.

Most stacks bolt verification onto authorization as an afterthought —
Arbiter was shaped around the idea that they are the same artifact at two
different quantifiers: *this request* versus *any request*.

## Boundaries (One-Line Reminders)

- Arbiter answers: *should this concrete request be allowed now?* (`Decided`)
- Soter answers: *can any modeled request violate this invariant?*
  (`Searched`, symbolic)
- Ferrox answers: *what is the best feasible plan?* (`Searched`,
  optimization)
- A future Lean lane answers: *can this invariant be checked as a theorem?*
  (`Verified`)
