# Authorization check: design and decisions

This document describes the `authorization` scanner as it stands on this branch:
what it treats as a privileged operation (a *sink*), what it treats as a check,
what it suppresses and why, and what it can still miss. Every rule has a decision
entry (`D<n>`) that records the alternatives that were rejected. Results of each
change on the Marketplace corpus are in [authorization-test-log.md](authorization-test-log.md).

Status at the head of this branch (corpus run `12-metadata-3`, 4745 apps scanned):
661 authorization findings in 252 apps, from 1507 findings in 295 apps at the reference
run. The unit changed from one finding per privileged operation to one per entry
(D10). The audit (`FORGE_LOG=authz_audit=debug`, run over the apps the reference run
reported on) sees 1618 privileged operations at the head (1507 at the reference run; 111 more are
found because helpers are retried after a suppressed operation, D4, and because of
the lowering fixes D13 and D14): 580 are suppressed by a rule and
1038 are reported, as 656 entries (661 findings in the full scan, which also covers
apps the reference run did not report on). Of those 656 entries, 393 hold an
operation the triage rated a true positive, 238 only operations it rated false
positive, 11 uncertain ones, and 14 are not in the triage (found by the callback fix).
Section 7 says what is left and why.

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
* One finding is created per entry (D10): the entry's first reported sink names it
  and the proof lists the others; `--authorization-report-operations` restores one
  finding per sink. The id (`check_name`) hashes the file, entry function and call
  chain of the first sink.

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

### D6 A flow analysis for resolver entries (`checkers/authz_flow.rs`)
Two rules (D7, D8) conclude that a read is harmless from the *absence* of a flow, so
the analysis must be sound before it is precise. It is a flow-insensitive,
alias-unifying may-flow analysis over everything a resolver callback can reach:

* One class per variable binding, temporary, function result and request response.
  Copies, phi joins, property reads and writes (field-insensitive), template and
  concatenation parts, arguments joined to the parameters of a resolved callee, the
  callee's result, and everything an *unresolved* call touches (receiver, arguments,
  result) are unified. A mutation through any alias therefore reaches every alias.
  Only operations that cannot carry data cut a flow: comparisons, `!`, `typeof`,
  `void`, `delete`, and reads of `length`, `size`, `ok`, `statusText`.
* Sources label classes: the request's `payload` (and `context.jobId` and any other
  property of the request) are *caller* data; `context` is *platform* data;
  storage, secrets, the environment, `fetch` and `asUser` responses are *external*.
  The request itself must stay intact: destructuring is followed, and the request
  may be handed to a function the analysis follows, but passing it anywhere else
  makes the analysis give up.
* Sinks mark classes as exposed: the resolver's return value; the body of a request
  (asApp or asUser) or the arguments of a call to a request client; outbound calls
  (`fetch`, an imported client, any call the analysis cannot classify as pure) and
  module-level state. A response used only in a route, a comparison, `length`, or a
  condition is not exposed. A `console` call is not an exposure.
* A request's response inherits the origins of what was sent (the route and body),
  without joining the classes, so that data derived from a read the caller steered
  is caller data too.
* Function values passed as call arguments, catch handlers and loop variables are
  lowered into side tables (`Environment::authz_closures`, `Body::authz_callbacks`,
  `authz_catches`, `authz_flow_links`) that the definitions table and the other
  scanners never see.
* Anything the lowering drops or approximates is recorded per function by
  `definitions/authz_lossy.rs` (`Body::authz_flow_gap`): function values that are
  not call arguments or bindings, classes and `this`, computed object keys,
  non-literal default values, rest parameters, generators, JSX, `new` of a
  non-identifier, dynamic `import`, `super`, `with`, `yield`, inlined array
  callbacks on a call result, and calls of a variable holding a function (object
  spreads and array callbacks that return were gaps until D14 and D13). If any function the entry reaches has
  one, or the budget (300 functions) is exceeded, the analysis fails and the
  finding is kept. The audit log records which construct it was (`flow`).

Known limits, accepted and documented: values moved through app storage, module
state or the platform between two resolver calls are not followed (a payload stored
by one resolver and used by another); errors raised by the runtime (a JSON syntax
error that quotes the body) are not exposures; module initializers are assumed to
be faithfully lowered; field-insensitivity means a response whose any part is
exposed counts as exposed.

Alternatives rejected: reusing the taint engine (`taint.rs`) as is. It copies
objects by value, so `list.push(response)` or a helper filling an argument loses the
flow, and it trusts unresolved calls to be pure. Making it sound needed a write-back
summary for every call and a heap model, which is a larger and riskier change than
a unification analysis that is sound by construction. Also rejected: running the
analysis per request (a fresh solve per sink) — one solve per resolver answers all
its requests; and lowering the dropped constructs into the shared IR, which would
change what every other scanner sees.

### D7 A read bound to the module context is not reported
A GET (or one of the read-only POST search endpoints) whose route and body are
reached by platform `context` data and by no caller-controlled or external value is
not reported. The caller already opened that issue, project or page in the product,
so the app reads what the caller is already looking at. `context.jobId`, storage,
asUser and fetch data, and any mix with caller data keep the finding; so does a
read with no context in it (an unscoped site-wide read is the data exposure the
scanner exists for), and every write.

Evidence (ordinal join with the triage): 64 findings rated false positive
(`FP-GUARD-CONTEXT`, `FP-NO-RESULT-EXPOSURE`, the context-sourced target and
context-bound resource classes, app-own data), 1 rated uncertain (a portal customer
view of an issue's raw JSON, where the product would also apply issue security),
0 rated true positive. Residual risk: `context.extension` is validated by the
product for browser calls only; invoked directly (the non-browser path of the FCT
trust analysis) a caller can fill it, and the asApp read can return more than the
caller may see (issue security, comment visibility).

### D8 A read whose response goes nowhere the caller can see is not reported
A GET or read-only POST whose response is not exposed (D6) is not reported: it only
decides control flow, counts, or names the next resource, whose own request is
reported if it is exposed. The 11 false positives and 6 rated true positives this
removes are in `docs/authorization-test-log.md`; five of the six sit in a group with
another reported operation, the sixth is a queue consumer that stores per-priority
counts of a board's backlog under a key built from the board id.
Writes are never exempted by what they return: of the 103 triaged POST, PUT, DELETE and PATCH
findings that return a constant or nothing, 60 are true positives.

### D9 Second tranche of metadata routes; a read's options and query are not exposure
The metadata table (D3) gains routes the triage rated false positive with no true
positive among them: one service desk by id and its request types (17 findings,
all false positives), the app's own `/myself`, field-context project and issue-type
mappings, field configuration schemes, `attachment/meta` and `project/{}/roledetails`.
`jql/parse` and `jql/sanitize` (POST) only analyse the query in the body and
return its structure (7 findings, all false positives); they are exempted by
route and method, as a separate class.

The flow analysis also stops counting the options of a GET, and the body of a
read-only POST search, as an exposure: they name what to read. A response that only
names the next resource in a search body (the board's filter id) is no longer kept
alive by it. Bodies of writes and of `asUser` requests still count.

Evidence: 28 findings removed, all rated false positive (see the log); no
true-positive row, and no group with a true positive, is affected.

### D10 One finding per entry
A resolver definition (or a handler function) is one finding, however many privileged
operations it reaches: the triage's own unit of triage ("154 resolver definitions,
251 rows") and the unit the scanner reported before it reported every operation. The
finding is identified by the id of the entry's *first* reported operation, which is
the id it already had, and its proof lists the other operations (method, route,
function and call chain). Nothing is dropped: every operation that survives the
policy is in the finding; `--authorization-report-operations` restores one finding
per operation, and the audit log (D1) still has one record per operation.

Alternatives rejected: grouping per finding id only (operations in different helpers
of one entry would still be separate tickets for one root cause: the entry lacks a
check); grouping per app (loses which resolver to fix); dropping all but the "worst"
operation (hides operations, and severity is constant). The triage verdicts are per
operation; an entry is a true positive if any of its operations is, which is how the
log counts entries.

This is a reporting-unit decision, not a precision gain: it is kept as its own commit
so that it can be reverted alone.

### D11 An action is a user entrypoint only if a Rovo agent lists it
An `action` module is invoked by a Rovo agent (a user chatting with the agent) or by
an Automation rule that an administrator wrote. The manifest tells which: a Rovo
agent module lists the actions it can call. An action no agent lists is
`BindingKind::Privileged` (D5): the inputs come from rule configuration, not from a
caller. An action an agent lists, or one whose function an ordinary module also
binds, stays an entrypoint. The triaged true positive on a Rovo-listed action (a
checklist agent) is unchanged.

Evidence: 8 findings (entries) in 8 apps leave the report, all rated false positive
(mostly `FP-ADMIN-ONLY`); no triaged true positive is affected.
Residual risk: an action that is both listed by an agent of another app is not
possible (agents list their own app's actions); a user who can edit an Automation
rule can already run the action with chosen inputs, which is what an administrator
configuring it is trusted to do.

### D12 Module context content that users edit is not the platform's to vouch for
D7 trusts `context` because the platform fills it. Not everything it carries is the
platform's: `context.extension.fieldValue` is the text of a custom field, and a macro
or a gadget delivers its saved configuration the same way; those values are chosen
by whoever can edit the field, macro or gadget, so a route built from them is as
user-controlled as one built from `payload`. Reads through a property named in
`CALLER_CONTROLLED_CONTEXT` (`jobId`, `fieldValue`, `gadgetConfiguration`,
`config`, `macro`, `properties`) are labelled caller data, including when the path
is the receiver of a method (`context.extension.fieldValue.split(',')`) or is read
through an alias or a destructuring. Everything else under `context` (identifiers of
the page: `extension.issue.key`, `extension.project.id`, `extension.content.id`, the
account, cloud and module ids) stays trusted.

Why: the triaged true positive `com.alexanderm.initiativepicker`'s "generic field
value resolver" reads `/rest/api/3/issue/${key}` for each key in the field value,
rated `TP-READ-USER-CONTROLLED` ("only provenance, not permission"). It was reported
only because the flow analysis could not follow the callback that parses the value
(D13); once it can, D7 alone would have suppressed it.

Corpus effect before D13: none (659 findings, 250 apps, the same decisions). The rule
is a guard for the flows D13 makes visible.

Rejected: an allowlist of the context paths the platform vouches for. The flow
analysis reads `context` once, when the handler destructures it, and a read of the
whole object is by far the commonest (211 of the 400 reads in the corpus audit); the
paths below it are not tracked, so an allowlist would either suppress nothing or have
to treat every whole-object read as caller data. A denylist of the content names errs
the same way for the paths it can see and documents the limit for the rest:
`Object.values(context.extension)` and similar aggregate reads keep their CONTEXT
label.

### D13 A callback that returns is a function that is called, not code pasted into the caller
`items.map(callback)`, `.filter`, `.forEach` and `.catch` on a plain identifier were
lowered by pasting the callback's statements into the enclosing function. A `return`
in the callback was then taken for the enclosing function's own: the block ended
there, so the instructions before the callback in that block and everything the
callback itself did were dropped, for every scanner. The scanner never saw a sink the
callback contained, nor a sink before the callback:

    resolver.define('batch', async ({payload}) => {
      await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`, {method: 'DELETE'});
      const rows = await Promise.all(payload.keys.map(async (key) => {
        const r = await api.asApp().requestJira(route`/rest/api/3/issue/${key}`);
        return r.json();
      }));
      await second(payload.key);
      return rows;
    });

reported only `second`; the DELETE and the read were invisible.

A callback whose block body contains a `return` is now lowered like the `.then`
callback already was: its own body (`__CALLBACK`), called with the receiver. Callbacks
without a `return`, and expression-bodied callbacks, are still pasted in and linked
to the receiver as before. Two details keep the flow analysis sound:

* the call's result is also joined with the receiver. `filter`, `find` and `sort`
  return the receiver's elements, not what the callback returns, so
  `data.values.filter((sla) => { return sla.ongoingCycle != null; })` still returns the
  data. (The first version did not join them and suppressed the triaged true positive
  `jsm.plugins.customer-portal-sla` `getSLAs`, whose response is exactly that. The
  regression test is `filtered_and_searched_collections_still_carry_the_data`.)
* the callback's frame is not shown. It is part of the function that wrote it, so a
  finding's stack, and therefore its id, is unchanged; the operation is described as
  "in a callback". The auth-header and secret-logging stacks are filtered the same
  way. A scanner that checks every function as an entry (auth-header, secrets) names
  the callback `__CALLBACK`, as it already named `__FULFILLMENT`.

Effect (corpus, run `10-callbacks`): authorization 659 → 666 findings, 250 → 253
apps. This is a recall fix, so the count goes up before the rules can apply:

* 22 findings appear and 15 disappear by id. Most of both are operations that moved
  between entries (a helper is visited once per run, and the first entry to reach it
  names it) or whose entry now reaches a sink it lost before: `getCustomerIssues`
  (reads an issue and its worklogs by key from a database query), `getStepAttachments`
  (reads an issue's attachments by the caller's key and returns their bytes),
  `getIssueChangelogs`, the comment-history custom field value functions and others.
  Spot-checked: the two entries above are true positives.
* the flow rules now apply inside callbacks: 22 more reads are `context-bound-read` and
  3 more `unexposed-read-response` (all 25 rows rated false positive or have no triage
  row; no new true positive group is lost), reported rows rated false positive drop from
  439 to 422.
* auth-header 93 → 94 findings (74 → 75 apps): a container token on an admin endpoint
  in a fetch inside such a callback, `de.techanics.bulkuseractions`. No other scanner
  changes.

Known false-negative risks that remain (accepted, listed for the captain):

* a callback with no `return` is still pasted into its caller, so a `throw` or
  `break` inside it is taken for the caller's;
* a callback passed to a method other than the ones in D13 and D16, or to a function
  of the app (`run(items, async (item) => {...})`), goes through the closure side
  table (D6), which the legacy checkers do not follow: a sink inside it is invisible
  to them but not to the flow rules;
* helpers are visited once per run, so which entry names a shared helper depends on
  entry order.

### D14 An object spread is lowered, not ignored
`{...expr}` lowered nothing for a spread of anything but a plain reference, so the
request inside `{...(await (await api.asApp().requestJira(...)).json())}` was never
seen and the flow through `{...(await response.json()), key}` was a gap (D6). Every
spread is now lowered and its value joined to the object. A spread of the response
is exposure when the object is returned; a spread of something unrelated is not.

Effect (corpus, run `11-spread`): authorization 666 findings in 253 apps (no
change at the finding level); four more operations are found (sinks inside spread
expressions), and six operations rated false positive are suppressed by the flow
rules (reported rows rated false positive 422 → 416). No true positive group is lost.
Tests: `spread_objects_carry_what_they_copy`.

### D15 Third tranche of site-level lookups
Three more GET routes join the instance-metadata table (D3, D9): the id of the Assets
workspace (`/rest/servicedeskapi/assets/workspace`, needed to call the Assets API and
the same for every viewer), the license state of an app
(`/rest/atlassian-connect/1/addons/{}/license`) and the app's own JQL function
precomputations (`/rest/api/:v/jql/function/computation`).

Evidence (run `12-metadata-3`): authorization 666 → 661 findings, 253 → 252 apps; 6
entries leave the report; reported rows rated false positive 416 → 411, one more row
rated true positive is suppressed (the workspace-id lookup of
`com.jaanga.assetsanalytics`, in an entry whose other operations stay reported). No
true-positive group is lost.

Why the table matters less here than it looks: a route whose text spells `user`,
`instance`, `avatar`, `license`, `preferences`, `serverInfo` or `group` (or any of
`TRIVIAL_API_PREFIXES`) is classified as a trivial route by `classify_api_call`, so it is
never a privileged operation for any method. That list is older than this work and is
applied to the route's spelling at the call, so it only fires for routes written inline;
the license route in the table is reached through a constant or a helper. The list is a
false-negative risk (`DELETE` of a group route, `PUT` of a user property). Left as is;
listed in the report.

### D16 Callbacks of `forEach`, `find`, `some`, `every`, `flatMap`, `sort`, `reduce` and `finally` are called
`lower_call` pasted the callbacks of `map`, `filter`, `catch` and `then` into the caller.
It also tested for `foreach`, which no JavaScript method is called, so `forEach`, the
commonest of them, and every other iteration method kept their callback in the side
table of D6, where the walk of the other checkers cannot see it:

    payload.keys.forEach(async (key) => {
      await api.asApp().requestJira(route`/rest/api/3/issue/${key}`, {method: 'DELETE'});
    });

was not a finding (nor were `find`, `some`, `every`, `flatMap`, `sort`, `reduce`).

Pasting the callback in is not an option for these: `x = items.find(cb)` would then
be the callback's expression, and the taint-based scanners (secret logging) lose the
flow from `items` to `x`. A first attempt that did paste them in dropped
secret-logging from 76 to 44 findings (three apps, 32 findings) before it was
replaced. The call is now lowered exactly as before (an unknown method called on the
receiver, so the result still carries the receiver for every scanner) and the
callback is *also* lowered as a function of its own (`__CALLBACK`) and called once, with
the receiver (`reduce`: the first value of the accumulator, then the receiver); what it
returns is joined to the call's result for the flow analysis. The callback is no
longer registered in the side table, which would have analysed it twice.

Effect (run `13-iteration`): authorization 661 → 662 findings, 252 apps, one new entry
(`com.develocenter.jira.links-scheme` `deleteFieldFromScreen`: an asApp
`DELETE /rest/api/3/screens/${}/tabs/${}/fields/resolution` in a resolver whose only
check is none: a write any caller can trigger, so a true positive that was invisible);
four more operations in all. secret 56 → 57 (one hard-coded secret inside such a callback);
secret-logging 76 findings in 16 apps unchanged (three ids move with their call path),
auth-header and authentication unchanged. Tests: operations in the callbacks of
every method are found; reduce carries the accumulator, `forEach` pushing response
data into a captured array is exposure and a counter is not.

## 5. Checks: what is recognised, what is verified

### 5.1 Recognition today (legacy, unchanged)
A path is *checked* when the walk meets an `authorize(...)` call or a request whose
route contains `permission` (`ApiCallKind::Authorize`), and the state stays checked
along every later instruction of the path and after any helper that checked
(`AuthorizeState`, a *may* analysis whose join is `max`). Nothing about the check is
verified: not that its result gates the sink, not that it names the same resource, not
that every path is gated.

### 5.2 What presence-only recognition hides
With recognition switched off (an experiment build, not committed:
`FSRT_EXPERIMENT_IGNORE_CHECKS`; run `X1-ignore-checks`) the scan reports 825
authorization findings in 314 apps instead of 666 in 253: **166 findings in 88 apps are
suppressed only because a check is present**. Three that were read:

* `io.prodbuddy.app addCommentToIssue`: `authorize().onJiraIssue(issueId).canEdit()`,
  then the asApp POST only `if (canEdit)`, on the same `issueId`. Enforced.
* `scrubzzly.rohn.eu orderIssueBeforeOther`: `authorize().onJiraIssue(issue).canEdit()`
  with `throw` on denial, then an asApp rank request whose body also names
  `rankBeforeIssue` from the payload, which no check covers. Partly enforced.
* `codeforme.development.versionmanager deleteVersion`: an asUser request to
  `/rest/api/3/mypermissions?permissions=BROWSE_PROJECTS` (no project, no issue), then
  an asApp `POST /version/${payload.id}/removeAndSwap` on a version id the caller
  chose. The probe cannot establish authority over that version. Not enforced: a
  finding the scanner hides.

So the presence rule is right often and wrong sometimes, and the three outcomes need
different handling. Making it strict would *add* findings (up to the 166), which is
why it is a policy decision for the captain and not a change made here (section 6).

### 5.3 What verifying a check would require
A check suppresses a sink only when all of these hold; each is checkable on the IR.

1. *Gate.* The sink is reachable only through the success outcome of a conditional
   whose condition derives from the check's result, with the polarity known
   (`res.ok`, `res.status === 200`, `canEdit`, `!res.ok` and so on), or the sink is
   after a call to a helper that throws unless the check passes. Removing the success
   edge from the CFG must make the sink unreachable.
2. *Resource.* The check's route and the sink's route name the same resource: the
   sink's route is the check's route plus literal segments, and the values in the
   holes are the same value (equal canonical access paths through single-assignment
   copies and the same parameter instantiated at the call).
3. *Strength.* A write sink needs a write check; a read check covers reads only.
4. *Exceptions.* A `try` whose handler can fall through to the sink breaks (1); the
   handler is not in the control flow graph, so this must be recorded at lowering.
5. *Identity.* The check was made as the caller (`asUser`, `authorize`), not as the
   app.

### 5.4 Shapes seen in the triage
Guard kinds the triager recorded on false-positive findings (rows; one finding can have
several): context-scoped resource 43, context-resource binding 19, app-level role
check inside a helper 11, helper that throws on a missing permission 9, `mypermissions`
probe inside a helper 9, group lookup by `context.accountId` inside a helper 9,
payload id compared with a context id 8, asUser same-resource request that throws on
failure 8, `authorize` API on an issue or a project 12, asUser search that supplies the
id set 5, context-derived resource id 5, context equality gate 5, asUser status gate 4.
Only the asUser same-resource, `authorize`-on-resource and throwing-helper shapes meet
conditions 1 to 5; the role and group shapes check an app-level role, which says
nothing about the resource, and the context shapes are D7 (reads) or a comparison the
analysis cannot decide.

### 5.5 What was tried, and why none of it is shipped
* A *class-based* same-resource test (both routes' holes in one flow class) was
  unsound: the flow classes merge values that flow through shared helpers and objects,
  and it gated a triaged true positive (`de.kyona.meeting`) on a check of a different
  resource. Replaced by the canonical-access-path test of 5.3, which is sound and
  recognised **one** finding; the remaining shapes need helper summaries (the guard is
  `fetchIssue(key)` or `assertProjectAccess(key)`), polarity analysis and try-region
  tracking. Archived outside the tree
  (`data/authz_noise_reduction_v2-night/experiments/user-gate`).
* An origin for data an asUser *listing* returned (search, board and sprint lists,
  Confluence page and space lists): an asApp read of ids that came from the user's own
  search reads only objects the user can browse. Sound for lists (an asUser read of one
  issue is not a listing: a parent or link may not be browsable) and it recognised
  **one** finding: the asApp request nearly always carries a caller-chosen field list or
  options object in the same flow class as the ids. Not shipped.
* Estimate for the full engine (helper summaries, polarity, try regions, resource
  sameness): about 20 of the 22 `FP-GUARD-ASUSER` and 23 `FP-GUARD-CUSTOM-HELPER`
  entries are candidates by guard kind; reading the code, six to ten fit all five
  conditions. About 1.5% of the report for several hundred lines of analysis in the
  lowering and the walker, with the risk 4 describes. Not built.

## 6. Policy options that need a decision

Every row is a rule that matches a real code signal and was evaluated offline on the
head audit against the triage (`tools/policy_eval.py`; "entries vanishing" means every
reported operation of the entry matches). None is applied.

| candidate suppression (GET unless stated) | operations: TP / FP / uncertain | entries vanishing | of which hold a TP operation |
|---|---|---|---|
| project by id and its versions, components, statuses, roles | 12 / 35 / 1 | 18 | 5 |
| board and sprint metadata | 19 / 12 / 0 | 12 | 8 |
| issue `editmeta` and `transitions` | 12 / 3 / 0 | 5 | 3 |
| property reads (issue, project, page, space, Forge app properties) | 5 / 23 / 0 | 15 | 3 |
| property writes (PUT, POST, DELETE of the same) | 25 / 28 / 0 | 28 | 15 |
| user search and lookup by id | 0 / 2 / 0 | 2 | 0 |
| group picker and bulk lookup | 0 / 2 / 0 | 2 | 0 |
| Assets schema, type and attribute metadata | 7 / 4 / 0 | 7 | 4 |
| `jql/autocompletedata/suggestions` | 2 / 1 / 2 | 3 | 1 |

A route class by itself is not separable: every class with enough rows contains rows
the triager rated true positive, because what separated them was what the caller
chose and what came back, not the route. The two classes with no true positive are
directory reads (users and groups), where the question is a product setting ("Browse
users and groups"), not a code signal.

Further policies the captain may want to weigh:

* *Verified checks* (5.3): strict mode would add up to 166 findings (5.2) and remove
  the guard false positives that meet 1 to 5. A strict mode behind a flag
  (`--authorization-verify-checks`) is the safe form.
* *Defines that only the platform calls*: every `resolver.define` is reachable through
  the frontend bridge by whoever can open a module bound to the resolver, including a
  define the app meant only for a queue consumer or an event listener, so they are
  entries (the queue consumer of `performancesavvy` is a triaged true positive that D8
  suppressed). Event and scheduled triggers are not entries at all
  (`into_analyzable_functions` ignores them).
* *Trivial routes* (D15 note): the list that turns a route into a non-sink should be
  replaced by a method-aware table.

## 7. Known false-negative risks and residual limits

False negatives the scanner has (not all introduced here; each one is a way a real
finding can be hidden):

1. Presence-only checks (5.2): up to 166 findings hidden by checks that may not be
   enforced.
2. The trivial-route list (D15): a route whose text spells `user`, `instance`,
   `avatar`, `license`, `preferences`, `serverInfo` or `group` is never a sink, for
   any method.
3. A helper is visited once per scan (D4): the first entry to reach it names the
   finding and a later entry with different inputs is not reported separately.
4. Legacy checkers do not follow a callback handed to anything but the methods of D13
   and D16 (`map`, `filter`, `catch`, `then`, `forEach`, `find`, `some`, `every`,
   `flatMap`, `sort`, `reduce`, `finally`), nor the second argument of a two-argument
   `then`; the flow rules do.
5. Catch handlers are lowered for the flow analysis but are not in the control flow
   graph the walker uses; a sink only a handler reaches is invisible to it.
6. Classes, `this`, and JSX are lowered lossily; the flow rules keep the finding in
   those cases, the walker may miss sinks in methods it cannot resolve.
7. Non-resolver entries (UI Kit functions, custom field value functions, web
   triggers) have no flow analysis: only the route table (D3, D9, D15) applies.

Residual limits of the suppressions (accepted, each documented at its rule):
D3/D9/D15: lists of containers (the project list of `de.syracom.jira.grc`, a
triaged true positive that left the report); D7/D12: `context.extension` can be filled
by a direct (non-browser) invocation, a read of the whole `context` object cannot be
refined; D8: values stored by one resolver and used by another (the queue consumer of
`performancesavvy`, a triaged true positive that left the report); D11: a user who can
edit an Automation rule can already choose an action's inputs; the asApp read can
return more than the caller may see (issue security, comment visibility), which no
route table can tell.

## 8. Reproduction

* Tests: `cargo test --workspace` (186 in `fsrt`, 15 in `forge_analyzer`, 14 in
  `forge_loader`); `cargo fmt --all -- --check`; `cargo clippy --workspace`.
* One app with decisions: `FORGE_LOG=authz_audit=debug fsrt --scanners authorization
  <app>` prints a JSON record per operation (`decision`, `flow`, `route_origin`,
  `body_origin`, `response_exposed`); `--authorization-report-operations` reports each
  operation as its own finding.
* Corpus: `scan_fsrt.py <rsm-zipped/assets> --timeout 60 --jobs 8` and, for the audit,
  the same binary with `FORGE_LOG` on the apps the reference run reported on. The
  scripts used to join the audit with the triage are in the task data directory
  (`tools/`).
