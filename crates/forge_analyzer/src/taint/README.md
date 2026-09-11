# Taint flow

`TaintDataflow<P>` is the opt-in forward analysis for scanners that need input trust
and source attribution. SQL injection is its first production consumer. The legacy
prototype-pollution, authorization, authentication, secret, and permission engines
retain their existing behavior.

## Value and policy contract

`FlowValue<F>` carries two independently joined components:

- `TaintValue`: `Trusted < Unknown < Untrusted`, plus structured `SourceOrigin`s.
- `F: PolicyFacts`: the consuming scanner's interpretation of sink safety.

`Trusted` is the join identity; an absent variable is not a trusted value. An
unreachable `FlowState::BOTTOM` differs from a reachable unknown value. Numeric
conversion and allowlist refinement update SQL safety without erasing input trust
or provenance. A SQL numeric-safe payload combined with an unresolved fragment
therefore remains Low, while an unsafe payload fragment remains High.

Origins identify a source rule, function, and argument or instruction site. They
contain no rendered paths or descriptions. `Origins` retains the least eight
unique keys, making bounded union associative, commutative, and idempotent.
Classification is computed independently, so truncation cannot downgrade trust.
Immutable origin sets are shared to keep CFG-state cloning inexpensive. Origin-only
changes count as state changes and participate in the fixed point.

## Adding sources and scanners

A `SourceDefinition` owns a stable unique ID, predicate, default classification,
and human-readable label. `FlowPolicy::sources` supplies scanner-specific rules;
these take precedence over the shared `FORGE_SOURCES` catalog. The policy can
override a rule's default classification through `source_classification`, without
repeating recognition or evidence labels. Add a source by adding one definition
and propagation/evidence tests, not a second match in a reporting traversal.

A scanner implements `PolicyFacts` and `FlowPolicy`, then chooses
`State = FlowState<Policy::Facts>` and `Dataflow = TaintDataflow<Policy>` on its
`Runner`. `NoFacts` is available when only generic trust matters. `classify_operand`
and `classify_variable` return the complete product value. Policies can supply
variable facts, operation facts, and guarded branch refinements. Sink matching,
severity, remediation, and rendering remain in the scanner.

The flow engine opts into joined function return states and caller-independent
callee visitation through `Dataflow` defaults inherited by `Runner`; legacy
engines retain their previous defaults. Use `run_checker_isolated_resolvers` for
entrypoint analysis: it resets analysis state before each entrypoint and resolver
callback while preserving the checker that merges findings.

## Propagation and compatibility

Assignments are strong updates. CFG edges and function summaries join values;
branch refinements survive only if all reachable predecessors establish them.
Exact projected values precede conservative root summaries. Assignment aliases,
argument projections, returned objects, arrays, templates, concatenation, and phi
nodes carry the complete value, including origins and policy facts. Callees and
callers are revisited when their incoming state or return summaries change.

Binding references and assignment versions are grouped by their resolved `DefId`
within each body, using a lazy index over finalized IR. Display names do not
establish identity: shadowed declarations remain independent, and synthetic
bindings use the same rule as named bindings. Values remain keyed by `VarId` and
projection; distinct bindings that reference the same object are not implicitly
merged. This is not a general JavaScript heap alias model. Static IR
fallbacks also preserve the existing constant/unknown classification behavior.
Recursive calls converge, but some recursive return shapes remain Unknown, as in
the compatibility baseline. No new sanitizers, heap semantics, or call-context
sensitivity are implied by this extraction.

`Rvalue::Array` is a compact array summary, including representative callback
results for supported `map` lowering. It does not promise exact array lengths or
per-index heap modeling. Naming the array kind explicitly prevents future object
aggregates from accidentally inheriting array-length semantics.

`CallFacts` retains neutral normalized path components, root binding, and import
identity at the call instruction's `Location`; it retains unresolved/computed
parts without embedding AST expressions. Candidate API matching belongs to the
scanner. Immutable receiver provenance is cached lazily only after a scanner asks
for it. This cache contains no resolver-specific taint and survives isolation. Finalized IR assignment locations are also indexed lazily, avoiding repeated whole-body scans during propagation. Like the existing CFG caches, these indexes are analysis-time views of immutable, lowered IR.

The engine never mirrors assignments or calls into `ValueManager`. Array literals
remain one instruction; the shared value engine continues to skip them. Constant-phi
expansion deduplicates input alternatives but has no fixed combination cap. The
eight-step local receiver search and cyclic alias protection remain in place.
Source and report-path limits remain eight.

## Validation

Core tests cover join laws, deterministic truncation, origin-only changes,
unreachable states, strong overwrites, exact projections, binding aliases, and
branch-refinement intersection. SQL integration tests check source locations and
categories through calls, returned objects, destructuring, branches, and arrays,
including the absence of unrelated or overwritten origins. They also exercise
numeric safety mixed with unknown and unsafe SQL, resolver isolation, recursive
convergence, and source overflow.
