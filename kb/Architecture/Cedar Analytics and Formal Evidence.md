---
tags: [architecture, cedar, analytics, evidence, verification]
source: mixed
date: 2026-05-13
---
# Cedar Analytics and Formal Evidence

This note records the current policy-assurance boundary after reviewing
`arbiter-policy`, `ferrox-solvers`, `prism-analytics`, Cedar Analysis, and
`cedar-spec`.

## Finding

`arbiter` is the right first place to expand the verification story.

The immediate need is not a new SMT solver crate or a custom Lean, Coq, or
Agda verifier. The first useful step is to use more of Cedar itself: validator
results, runtime policy tests, and Cedar Analysis / symbolic compilation.

## Current Capability Map

| Project | Current role | Evidence style |
|---|---|---|
| `arbiter-policy` | Cedar-backed runtime authorization, delegation checks, gate suggestors | `Decided` |
| `ferrox-solvers` | CP-SAT, LP, MIP optimization and bounded feasibility | `Searched` |
| `prism-analytics` | Analytics, fuzzy inference, feature extraction, ML-style suggestors | `Observed` / `Argued` |
| Cedar Analysis / SymCC | Symbolic policy analysis and concrete counterexample search | `Searched` / `CounterexampleFound` |
| future Lean path | Checked predicates/theorems over declared models or `cedar-spec` | `Verified` |

Every promoted fact needs provenance. Only selected high-risk claims need
formal-proof evidence. A Cedar decision, solver result, fuzzy inference output,
or recall result can be valid provenance without being a formal proof.

Reserve `Verified` for claims backed by a checked artifact from Lean, Coq,
Agda, or an equivalent trusted checker.

## Cedar-First Decision

Arbiter should use this lane before adding a separate proof-assistant layer:

```text
Gherkin invariant
  -> review fixture matrix for model adequacy
  -> Cedar policy and schema validation
  -> Cedar runtime regression test
  -> Cedar Analysis / symbolic compiler query
  -> counterexample or no-violation result
  -> evidence attached to the Converge promotion path
```

The analysis result is high-assurance evidence, not direct promotion authority.
Converge still owns promotion and decides which claim classes require which
evidence.

The hard part is model adequacy, not proof technology. A solver or proof
checker can only answer questions about the encoded model. The first Arbiter
conditional query therefore exposes its Cedar claim policy and carries review
fixtures that define the positive business case plus boundary cases that must
fall outside the claim. Negative mutant-policy tests show that a policy that
allows the positive claim fixture is visibly unsafe even before proof tools are
considered.

## Formation Discovery

Arbiter exposes Formation-facing capability descriptors under the stable
`arbiter.cedar` family:

| Capability | Surface | Tier |
|---|---|---|
| `arbiter.cedar.policy_gate` | `PolicyGateSuggestor` / `policy-gate` | `Decided` |
| `arbiter.cedar.hitl_gate` | `CedarHitlGateSuggestor` / `cedar-hitl-gate` | `Decided` |
| `arbiter.cedar.analysis_evidence` | `CedarAnalysisSuggestor` / `cedar-analysis` under `analysis` | `Searched` |

This is intentionally a catalog, not a `converge_pack::Pack`
implementation. Runtime policy gates are Suggestors. Offline Cedar Analysis
produces evidence. Converge remains responsible for promotion decisions.

## Runtime HITL Gate

HITL escalation is part of Cedar runtime policy, not a generic fallback.
Arbiter now treats a Cedar denial as `Escalate` only when the same request with
`human_approval_present = true` would be allowed by Cedar. If approval would
not change the Cedar decision, Arbiter returns `Reject`.

This keeps the boundary pragmatic:

- Cedar decides the current request.
- Arbiter may probe Cedar for the approved version of the same request.
- Converge receives `Promote`, `Escalate`, or `Reject`.
- Hard stops such as wrong domain, missing gates, or unsupported authority do
  not become HITL tasks unless Cedar explicitly allows the approved path.

## Cedar 4 Upgrade Status

Arbiter has been upgraded from `cedar-policy = 2.4` to the Cedar 4.10 line.

This aligns Arbiter with the Cedar line used by current symbolic-analysis
crates. For example, `cedar-policy-symcc 0.4.0` depends on
`cedar-policy = 4.10.0`.

The optional Arbiter `analysis` feature now wires in `cedar-policy-symcc` for
schema parsing, policy validation, request environment enumeration, symbolic
compilation, stable preparation hashes, solver execution, and counterexample
capture. Solver execution accepts a caller-supplied SymCC solver; the CVC5
helper resolves `CVC5` first and then `cvc5` on `PATH`.

`CedarAnalysisSuggestor` is the Converge-facing wrapper around this lane. It
reads typed `CedarAnalysisInput` payload facts, calls a
`CedarAnalysisBackend`, and emits typed `CedarAnalysisReport` proposals. The
backend trait lives in Arbiter so product assemblies can provide a solver
implementation without making Arbiter depend on another extension crate.
`CedarAnalysisReport` is payload v2 and carries shared Converge
`ExecutionIdentity` metadata. The default caller-supplied SymCC solver lane
records non-native execution identity; `LocalCvc5AnalysisBackend` records a native
external-process identity for the resolved CVC5 binary.

The workspace integration harness now has a `soter-cvc5` feature that wires:

```text
CedarAnalysisSuggestor
  -> Arbiter Cedar/SymCC generated SMT
  -> Soter CVC5 FFI backend
  -> CedarAnalysisReport
```

That bridge proves the generated SMT is tied to Arbiter's real Cedar policy
model rather than only Soter's hand-coded abstract fixture.

## CVC5 CI Policy

CVC5 support currently means Arbiter can execute SymCC-generated SMT assertions
with a local CVC5 process and map the result into a `CedarAnalysisReport`.
That is useful integration evidence, but it is still `Searched` evidence and
not formal proof evidence.

Current operational status:

- Soter has proven native CVC5 execution through its FFI backend.
- The workspace integration harness exercises Arbiter's real Cedar/SymCC model
  through Soter CVC5 using the `soter-cvc5` feature.
- Arbiter's own local-CVC5 smoke tests exist, but they are ignored by default
  and require `CVC5` or `cvc5` on `PATH`. Because that path is not yet run as a
  scheduled/manual CI job, it is not a routinely exercised Arbiter gate.

The policy is explicit:

- Required PR/push CI runs `cargo test --workspace --all-targets --all-features`.
  These tests use a fake in-process solver so every runner can validate SymCC
  compilation, status mapping, report shaping, and counterexample capture.
- Real CVC5 runs only in scheduled/manual CI through an ignored smoke test. It
  catches external solver drift and CVC5/SymCC compatibility breaks.
- Real CVC5 invariant assurance must use conditional invariant queries for
  actual claims. Broad `AlwaysDenies`/`AlwaysAllows` queries still validate the
  analysis lane, but they do not by themselves support a full
  natural-language invariant.

The first useful conditional query should target the existing expense claim:
non-finance principals cannot commit high-value expense resources even when
receipt, manager approval, and explicit human approval are present.

Arbiter now exposes that first query as
`ExpenseNonFinanceHighValueCommitDenied`. It builds a Cedar policy describing
the high-risk claim space and asks SymCC/CVC5 whether that policy is disjoint
from the real expense approval policy's allowed requests. `NoViolation` means
the solver found no modeled request that both satisfies the claim condition and
is allowed by the real policy.

The encoded claim policy is a public review surface:
`EXPENSE_NON_FINANCE_HIGH_VALUE_COMMIT_CLAIM_POLICY`. The review fixture lives
at `crates/arbiter/invariants/expense_non_finance_commit_review.md`.

The broader high-risk claim portfolio is product-side, not hidden inside
Arbiter. Atelier carries the Truth/scenario exemplar; Arena carries
cross-extension smoke tests for expense, strict HITL, vendor due diligence,
flow gates, and data classification. This keeps the expense conditional query
as the worked exemplar rather than pretending it is portfolio coverage.

## Ferrox Boundary

`ferrox-solvers` is an optimization and feasibility extension, not a general
SMT layer.

The current OR-Tools wrapper exposes a narrow C ABI over:

- CP-SAT integer and boolean variables.
- Linear `<=`, `>=`, and `=` constraints.
- `AllDifferent`.
- Fixed and optional intervals.
- `NoOverlap`.
- `Circuit`.
- Objective minimization and maximization.
- GLOP continuous LP variables, row constraints, and objective solve.

The vendored OR-Tools C++ library contains more than this wrapper exposes,
including richer CP-SAT constraints, routing, graph algorithms, assignment,
knapsack, MathOpt, and PDLP. That broader C++ surface is still optimization and
constraint programming infrastructure, not a native SMT front end.

Important local note: the Ferrox docs mention OR-Tools `v9.15`, but the current
vendored checkout/build reports OR-Tools `v9.11`. Reconcile that before
expanding the OR-Tools wrapper.

## Arbiter Boundary

Arbiter answers:

```text
Should this concrete principal/action/resource/context be allowed now?
```

Cedar Analysis should answer:

```text
Can any modeled Cedar request exist that violates this invariant?
If yes, what is the counterexample?
If no, which policy, schema, query, and Cedar versions support that result?
```

Good first targets:

- Gherkin-facing invariant syntax that compiles into Cedar test vectors.
- Runtime regression tests for each invariant.
- Schema artifacts for reference policies.
- Cedar Analysis preparation and solver execution over high-risk invariants.
- Stable JSON reports containing policy hash, schema hash, query hash, Cedar
  version, status, and counterexample details when present.

The analysis layer must not promote facts directly. It should emit proposals or
evidence that the Converge promotion path can evaluate.

## Lean Predicate Boundary

Lean predicates should arrive after Cedar Analysis has been exhausted for at
least one high-risk Arbiter invariant.

Initial Lean work should prove theorems over a declared abstract model, for
example:

```text
For all principals, invoices, and contexts:
if the principal is not Admin and invoice amount > 10000,
then the abstract approval policy denies approval.
```

Do not call that a Cedar proof unless the proof targets real Cedar semantics,
such as the upstream `cedar-spec` model. Until then, label the scope explicitly:

```text
scope = "generated abstract policy model"
```

The Lean driver should:

- Check a theorem artifact with Lean 4 and Lake.
- Enforce a timeout.
- Hash source, toolchain, and output.
- Run `#print axioms theorem_name`.
- Reject `sorryAx` and non-whitelisted axioms.
- Return evidence for promotion, not direct facts.

## SMT Boundary

An SMT crate remains useful, but it is not the first step.

SMT should be introduced when Arbiter analytics needs symbolic counterexample
search beyond finite matrix enumeration. A future `ferrox-smt` or `smt-gates`
should target Z3 first and CVC5 later, with a result model like:

```text
sat | unsat | unknown | timeout
```

Use SMT to ask:

```text
Can any modeled request exist that violates this invariant?
```

Use Lean to ask:

```text
Can this invariant be checked as a theorem over stated assumptions?
```

## Prism Boundary

Prism fuzzy logic is graded inference, not hard authorization or proof.

Fuzzy inference can provide risk, suitability, or expectation signals. Arbiter
can gate actions using those signals if products choose policy thresholds, but
the fuzzy result itself is not a formal proof and should not override Cedar.

If fuzzy logic is later connected to formal methods, start with interval or
rational certificates for piecewise-linear membership functions. Avoid treating
raw floating-point Gaussian membership results as mathematical proof evidence.

## First Invariant

Start with a crisp invariant that already matches the reference expense policy:

```gherkin
Scenario: Non-finance cannot commit a high-value expense
  Given a supervisory persona outside the finance domain
  And a high-value expense with receipt and manager approval gates passed
  And explicit human approval is present
  When the persona attempts to commit the expense
  Then Arbiter must reject the decision
```

This fixture can become:

- a Cedar runtime regression test now,
- a Cedar Analysis query after the Cedar 4.x upgrade,
- ordinary evidence for Converge promotion later.

## Recommended Sequence

1. Add Gherkin invariant fixtures and runtime regression tests.
2. Add schema artifacts for reference policies.
3. Add optional Cedar Analysis preparation backed by the symbolic compiler.
4. Add solver execution and counterexample capture for selected invariants.
5. Emit pinned analysis artifacts as ordinary evidence.
6. Add conditional Cedar Analysis queries for selected high-risk invariants.
7. Promote real CVC5 from nightly smoke to required invariant evidence only
   when those conditional queries encode actual Arbiter claims.
8. Revisit custom Lean only for claims Cedar Analysis cannot express.

## Non-Goals For The First Step

- Do not build a generalized `certus-verify` framework yet.
- Do not claim Ferrox provides SMT.
- Do not label generated abstract-model proofs as Cedar runtime proofs.
- Do not require formal evidence for every promoted fact.
- Do not formalize Prism fuzzy logic before hard policy invariants are useful.
