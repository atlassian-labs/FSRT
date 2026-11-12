# Authorization check: what is reported and what is not

The authorization scanner reports an `asApp()` request (or a call to a Forge remote with an
app system token) that the walk of an entrypoint reaches without a recognised
`authorize()` check. This page records the rules that decide, after the walk reached such an
operation, whether it is reported. Each rule suppresses on a code signal, never because a check
was verified: a suppression is not evidence of authorization.

## 1. What is reported

* One finding per walk. The walk of an entrypoint ends at the first operation that is
  reported, as it always has; an operation a rule suppresses leaves the walk running, so a
  later operation of the same entry can still be reported (`AuthZChecker::found`).
* The finding id (`Custom-Check-Authorization-<hash>`) is unchanged: it hashes the source path,
  the entry and the call chain.
* Manifest aliases that bind one exported handler are analysed once; the proof lists every
  invokable binding (`scan_directory`).
* The interpreter visits a helper once per scan, so a helper is credited to the first
  entrypoint that reaches it. A helper that only leads to suppressed operations is retried for
  later entrypoints (`suppressed_helpers`, `Interp::retry_checker_functions`); a helper on the
  path of a reported operation is not.

## 2. Audit log

`FORGE_LOG=authz_audit=debug` prints one JSON record per decision: finding id, ordinal within
the id, entry, function, method, route, the decision (`reported` or the rule that suppressed
it), whether the flow analysis completed, and the route origin, body origin and response
exposure it computed. Joining it with triage verdicts is how each rule was evaluated.

## 3. Request facts

Lowering records the HTTP method and route text of each `requestJira`, `requestConfluence` and
`requestBitbucket` call (`definitions/authz_request.rs`, `request.rs`). Inline literals are read
from the AST and `const` bindings are followed. Spreads, computed keys, accessors, `__proto__`,
a method that is not a literal, `let` and `var` bindings and calls with more than two arguments
are unknown, and every rule needs a proven fact: an unknown fact keeps the finding.

## 4. Rules

| decision | what is suppressed | where |
|----------|--------------------|-------|
| `principal-branch-unreachable` | operations on branches no analysed call context can take (a helper that picks `asApp()` or `asUser()` from a boolean parameter the resolver passes as a literal) | `checkers/authz_principal.rs` |
| `instance-metadata-route` | a proven GET of site configuration every user already sees in forms and pickers (fields, issue types, statuses, priorities, project/board/space lists, ...) | `checkers/authz_routes.rs` |
| `query-analysis-route` | POST `jql/parse` and `jql/sanitize`, which return the structure of the query | same |
| `context-bound-read` | a read whose route and body are reached by the module `context` and by nothing the caller controls or stored | `checkers/authz_flow.rs` |
| `unexposed-read-response` | a read whose response reaches neither the returned value, a request body, an outbound call nor module state | same |
| `no-caller-data-write` | a write (any method but GET and DELETE, or a request with no method of its own such as GraphQL) whose route and body carry no payload and no external value | `flow_suppression` |
| `own-property-key` | any method on a route with a `properties` segment whose route carries no payload | same |
| privileged bindings | functions bound only by assets-import hooks or `compass:adminPage` are not user entrypoints | `forge_loader/src/manifest.rs` |

Writes are never excused by what they return. A DELETE and a REST request whose method could not
be proven are always kept.

## 5. The flow analysis

`checkers/authz_flow.rs` is a flow-insensitive, alias-unifying may-flow analysis over the IR
reachable from one resolver callback. A value's class carries the origins that may reach it
(payload `1`, platform context `2`, external `4`: storage, secrets, environment, `fetch`,
`asUser` responses) and where it may go. A rule that concludes from the absence of a flow is
only as good as the analysis is complete, so:

* anything the lowering drops (`definitions/authz_lossy.rs`: classes, `this`, JSX, generators,
  rest parameters, default values, computed keys, an object spread of anything but a plain
  reference, `with`, ...), a call of a function value, a request object that escapes the
  callback, or an exhausted budget makes the whole analysis fail for that root and every flow
  rule keeps its findings. One construct the analysis cannot follow anywhere under a root
  switches the flow rules off for all of that root's operations;
* only comparisons, `!`, `typeof` and the length-like reads of `SCALAR_PROPERTIES` cut a flow,
  and a scalar read still takes the origin of the value it is read from;
* the module `context` is trusted except for the names in `CALLER_CONTROLLED_CONTEXT`
  (content users edit: `fieldValue`, `config`, `gadgetConfiguration`, `macro`, `properties`,
  and the job id). A name the platform adds later is trusted until it is listed;
* entrypoints that are not resolvers have no flow, so only the route table applies to them.

## 6. Known limits

* The call of an imported function with no caller-derived argument has no origin, so its result
  is not external: a write built from it counts as carrying no caller data.
* A GraphQL or other non-REST request has no method and counts as a write; a constant query is
  not reported.
* A fixed destructive POST, PUT or PATCH is not reported; a DELETE is.
* A property value that comes from the payload is still written when the key is not the
  caller's: `own-property-key` judges the key only.
* A shared helper is credited to the first entrypoint that reaches it, so the per-entry count
  depends on the order of the manifest.

## 7. Measuring a change

Run the scanner over the corpus with `--scanners authorization`, once per tree, and compare
the findings per entry and per app; run it again with `FORGE_LOG=authz_audit=debug` to see which
rule decided each operation. Keep every other scanner's findings identical to main's.
