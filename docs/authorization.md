# Authorization check: design and decisions

This document describes the `authorization` scanner as it stands on this branch:
what it treats as a privileged operation (a *sink*), what it treats as a check,
what it suppresses and why, and what it can still miss. Every rule has a decision
entry (`D<n>`) that records the alternatives that were rejected. Results of each
change on the Marketplace corpus are in [authorization-test-log.md](authorization-test-log.md).

A finding is a review candidate, not proof of an exploitable flaw, and a
suppression is not proof that the code is authorized. Rules are kept only when
they match a real signal in the code and were justified against the per-finding
triage verdicts (879 FP, 609 TP, 19 uncertain over the 1507 findings of the
reference corpus run).

## 1. What the scanner reports

A finding means: from a user-invokable Forge function (a manifest `function`
bound to a UI, product or `action` module), some path reaches
`api.asApp().request{Jira,Confluence,Bitbucket,Graph}(...)` (or a Compass
`asApp` GraphQL call) and no recognised check was seen on the path before it.
The call is a *sink* because the app, not the user, supplies the credentials.

* Checks (legacy, unchanged): `authorize(...)` from `@forge/api`, or any request
  whose first argument contains the substring `permission`. The result of a
  check is never inspected; a check on one path suppresses later sinks on all
  paths (a *may* analysis).
* The walk visits each helper function at most once per scan, except helpers on
  the call path of a suppressed operation, which are retried for later roots.
* One finding is created per sink reached. The id (`check_name`) hashes the
  file, entry function and call chain, so several sinks in one function share it.

## 2. Operations, candidates and audit

The walk of a root (a `resolver.define` callback or a handler function) collects
*candidates*: privileged operations reached without a recognised check. When the
walk of the root is complete, a policy decides for each candidate whether it is
reported (`AuthZChecker::decide`). Suppressions made during the walk (unreachable
branches, resolver-level GET policies) are logged when they happen.

`FORGE_LOG=authz_audit=debug` prints one JSON record per decision with the finding
id, the ordinal of the candidate within that id, the entry, the function holding
the sink, the HTTP method, the route and the decision. Suppressions never enter the
stdout report and are never evidence of authorization.

## 3. Request facts

`forge_analyzer::request` records the HTTP method and route text of every
`requestJira`, `requestConfluence` and `requestBitbucket` call during AST lowering
(`definitions/authz_request.rs`), keyed by IR location:

* method: omitted options mean GET; an inline options literal without
  spread, computed key, accessor or `__proto__` gives the literal `method`
  (case-insensitive) or GET if absent; anything else is unknown;
* route: a string literal, a template, a `route` template imported from
  `@forge/api`, or a `+` concatenation with at least one literal part. Holes stand
  for non-literal parts;
* an identifier that names a `const` binding is resolved lazily from the binding's
  initializer (`Environment::authz_consts`), so declaration order does not matter;
  `let` and `var` bindings are never trusted.

Unknown facts must be treated as the most privileged alternative by every rule.

## 4. Decisions

### D1 Candidate collection and audit instead of immediate reporting
Sinks used to be pushed to the report from inside the walk, so a rule could not
use anything learned later in the same root (for instance, whether a response
reaches the return value). They are now collected and decided when the root
completes. Alternatives rejected: a second walk per root (doubles the traversal
and risks diverging from the first); post-filtering the final report (loses the
call stack and ordinal needed to explain a decision).

### D2 Request facts are read from the AST at lowering time
The IR keeps the route template but not the options object faithfully: object
spreads, computed keys and methods are dropped by the lowering, so a method read
from the IR could wrongly look like GET. The AST call is exact for what it names.
Alternative rejected: recover the method from IR property writes (unsound because
of the dropped constructs above).

### D3 Instance-metadata GET table (`checkers/authz_routes.rs`)
A GET whose route names instance configuration metadata is not reported. The
table is a list of anchored path patterns (`:v` is the REST version, `{}` one
segment), matched against the route's path segments, never against substrings.
A route whose matching segment is computed does not match a literal one, the
query string is ignored, and the method must be a proven GET.

Evidence: of the 646 triaged GET sinks that this table matches, the triage rated
303 false positive (`FP-READ-ONLY-METADATA`) and the 19 rows it rated true
positive are all sinks in a group (same finding id) whose real exposure is another
operation that is still reported, except one: `getProjectsPage` of a governance
app reads `/project/search` and then versions of every project through a helper
that the walk had already visited for another resolver (the visit-once
limitation). That finding is the only true positive group lost, and the
operation behind it is still reported under the other resolver.

Alternatives rejected:
* a substring or regex over the route (the legacy `user|instance|avatar|...` regex
  makes `/properties/userPrefs` safe and misses `/field/search`);
* allowing any GET with a constant route: `/rest/api/3/issue/ONE` or
  `/project/KEY/role/10002` name one resource and carry data the caller may not see;
* including routes with a computed segment, such as `/project/{key}`, whose raw
  response was the exposure in the triaged true positives;
* suppressing every GET of a read-only verb: `search/jql`, board configuration,
  sprint issues, attachments and Confluence pages are GETs or POST reads of
  content, and 242 of the triaged GET sinks are true positives.

Known residual risk: project, board, service desk and space *lists* disclose the
names of containers the caller may not be allowed to browse. The triage rated these
lists false positive; a policy owner may want them back as low severity.

### D4 Retry helpers only while nothing on their call path is reported
When the policy suppresses an operation, the helpers on its call path are visited
again for later resolvers so that a suppressed read cannot hide a write in the same
helper (the legacy visit-once set would otherwise hide it). Retrying every helper on
the path of any suppressed operation also re-reports the helper's *other*, reportable
operations under every later resolver, which is not what the retry is for. The
retry now excludes any helper that is on the call path of a reported operation.
Measured effect with D3 alone: 14 additional findings without the exclusion, none
with it.

### D5 Platform-invoked and product-admin-only modules are not unprivileged entrypoints
A manifest registration now has a third kind, `BindingKind::Privileged`, for
modules only the platform or a whole-product administrator can reach:
`jiraServiceManagement:assetsImportType` (the platform calls `startImport`,
`stopImport`, `importStatus` and `onDeleteImport` with the stored import
configuration) and `compass:adminPage` (consistent with `jira:adminPage`, which
was already not an entrypoint). A function is analysed as an entrypoint only if an
ordinary (invokable) module also binds it; the privileged bindings are kept in the
evidence.

Evidence: 14 findings in four apps are reported on assets-import hooks and were all
rated false positive (13 `FP-ADMIN-ONLY`, 1 `FP-NO-RESULT-EXPOSURE`).

Rejected: treating `jira:projectSettingsPage` and `confluence:spaceSettings` the
same way. Project and space administrators are not product administrators, and two
triaged true positives are exactly this elevation (a project settings page whose
resolver runs a payload-supplied JQL as the app, and one that rewrites global
workflows). Also rejected: `action` modules, which are user-reachable when a Rovo
agent lists them, and `automation:actionProvider`-style modules are not parsed.
