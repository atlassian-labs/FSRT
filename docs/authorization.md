# Authorization check: what is reported and what is not

The authorization scanner reports an `asApp()` request (or a call to a Forge remote with an
app system token) that the walk of an entrypoint reaches without a recognised
`authorize()` check. This page records the rules that decide, after the walk reached such an
operation, whether it is reported. Each rule suppresses on a code signal, never because a check
was verified: a suppression is not evidence of authorization.

## 1. What is reported

* One finding per walk, and a write is preferred to a read (`AuthZChecker::found`, `decide`):
  the finding of an entry is the first reported operation that is shown to write (POST, PUT,
  PATCH or DELETE, through an options object whose `method` the interpreter resolves to a
  literal, or to one of several literals one of which is a write) and, when there is none, the
  earliest reported operation. The walk ends at that write. A reported operation that is not
  shown to write (a GET, a request with no `method`, a `method` that cannot be resolved, a remote
  call, a custom-field read) is kept as the candidate and the walk goes on in case a write
  follows. An operation a rule suppresses neither ends the walk nor displaces a finding, so a
  later operation of the same entry can still be reported. Which operations are findings is
  unchanged; only which one is reported when an entry has several.
* The finding id (`Custom-Check-Authorization-<hash>`) is unchanged: it hashes the source path,
  the entry and the names of the functions on the call chain of the reporting operation. It does
  not hash the method or the instruction, so a write reached through other helpers than the GET
  it replaces is a different finding, while a write made from the same function as the GET keeps
  the id.
* Manifest aliases that bind one exported handler are analysed once; the proof lists every
  invokable binding (`scan_directory`).
* The interpreter visits a helper once per scan, so a helper is credited to the first
  entrypoint that reaches it. A helper that only leads to suppressed operations is retried for
  later entrypoints (`suppressed_helpers`, `Interp::retry_checker_functions`); a helper on the
  path of a reported operation is not. What the walk reached after the entry's first reported
  operation, while it looked for a write, is not claimed either: the visited set is restored to
  that point when the walk is over (`visited_at_first`). The helpers of a reported operation that
  a write supersedes stay claimed, as they were when the walk stopped at the first finding.

## 2. Audit log

`FORGE_LOG=authz_audit=debug` prints one JSON record per decision: finding id, ordinal within
the id, entry, function, method, route, the decision (`reported`, the rule that suppressed it,
`superseded-by-write` for a reported operation that a write replaced, or `later-finding-of-entry`
for one after the entry's finding), whether the flow analysis completed, and the route origin, body origin and response
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
| `own-property-key` | any method on a route with a `properties` segment whose route carries no payload | `flow_suppression` in `checkers.rs` |

A write is reported whatever it returns and whatever it carries: a fixed POST, PUT or PATCH, a
GraphQL call with a constant query, a write built from the platform `context` and a REST request
whose method could not be proven are findings, and so is a DELETE. The one exception is a property
whose key the caller does not choose (`own-property-key`), judged by the route only.

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
* only comparisons, `!`, `typeof` and the length-like reads of `SCALAR_PROPERTIES` (`length`,
  `size`, `ok`, `statusText`) cut a flow, so a count or flag carries neither the origin nor the
  exposure of the value it is read from (see the known limits);
* all of the module `context` is trusted (`request_read`): every `context.*` value counts as
  the platform's, the job id included. The rule is deliberately simple until there is a more
  robust way to track which context fields the platform vouches for (see the known limits);
* entrypoints that are not resolvers have no flow, so only the route table applies to them.

## 6. Known limits

* The call of an imported function with no caller-derived argument has no origin, so its result
  is not external: a read built from it and the platform `context`, or a property route built
  from it, counts as carrying no caller data.
* Writes are not suppressed: a fixed write, a GraphQL call with a constant query and a write
  built from the platform `context` are findings, although some of them are not exploitable.
  Narrower write rules (a route that names the app's own data, read-only POST searches, guards
  found in the context, more metadata routes) are a possible follow-up, not part of these rules.
* A property value that comes from the payload is still written when the key is not the
  caller's: `own-property-key` judges the key only.
* A count or flag of caller data, such as `payload.items.length` or `payload.size`, is not treated as
  caller data: a read or a property route built from it counts as carrying no caller data,
  although the caller can choose the count. This is accepted: the cut keeps `response.ok` and
  `items.length` from making a response look exposed, and the analysis has no way to keep one
  without the other.
* A shared helper is credited to the first entrypoint that reaches it, so the per-entry count
  depends on the order of the manifest.
* An unproven `method` ranks with GET: a request whose method cannot be resolved to a literal
  (`req.method`) is not a write for the preference, so a proven write is reported instead of it
  and it is never preferred. The class comes from the interpreter's value of `options.method`
  (`AuthZChecker::request_class`) while the rules use the method proven at lowering
  (`definitions/authz_request.rs`); they can disagree on a `let` binding, which only changes
  which operation is reported, never whether an operation is suppressed.
* Content that users edit and the platform puts in `context` is treated as vouched-for: a custom
  field's value (`context.extension.fieldValue`), a gadget's or macro's configuration, the
  properties of a request, and the job id. A read whose route or body is built only from them is
  not reported, although whoever can edit that content steers the request. One triaged true
  positive is given up this way (the initiativepicker "generic field value resolver",
  TP-READ-USER-CONTROLLED); on the corpus it is still reported today, only because the flow
  analysis gives up on that resolver (an inlined callback with a block body) and every flow rule
  keeps its findings there. The follow-up is an allowlist built from the platform's list of
  context fields, so that only the fields it vouches for are trusted.
* The lifecycle hooks of a `jiraServiceManagement:assetsImportType` module (`startImport`,
  `stopImport`, `importStatus`, `onDeleteImport`) and the function of a `compass:adminPage` are
  analysed like any other module function. Their callers are unproven: the module's own
  documentation only excludes unlicensed users, so licensed users have access by default, and who
  can reach the Imports screen has not been verified. Treating them as platform-only or
  admin-only hid 6 entries in four apps (14 triaged findings, all rated false positive); that
  rule was dropped, and these hooks are analysed until the reachability is established.

## 7. Measuring a change

Run the scanner over the corpus with `--scanners authorization`, once per tree, and compare
the findings per entry and per app; run it again with `FORGE_LOG=authz_audit=debug` to see which
rule decided each operation. Keep every other scanner's findings identical to main's.
