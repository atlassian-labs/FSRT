# Authorization check: what is reported and what is not

The authorization scanner reports an `asApp()` request (or a call to a Forge remote with an
app system token) that the walk of an entrypoint reaches without a recognised `authorize()`
check. This page records the rules that decide, once the walk has reached such an operation,
whether it is reported. A suppression is made on a property of the request, never because a
check was verified: it is not evidence of authorization.

## What is reported

* The walk of an entrypoint ends at the first operation that is reported. An operation a rule
  does not report leaves the walk running, so a later operation of the same entrypoint can still
  be reported (a read of field metadata does not hide the write after it).
* The finding id (`Custom-Check-Authorization-<hash>`) hashes the source path, the entrypoint and
  the names of the functions on the call chain. It does not depend on the rules below.
* Manifest aliases that bind one exported handler are analysed once. The proof of the finding
  lists every invokable binding, and the finding id is the one the handler had before.
* The interpreter visits a helper once per scan. A helper that only led to operations that were
  not reported is made visitable again for the entrypoints that follow; a helper on the path of a
  reported operation is not.

## Request facts

Lowering records the HTTP method and the route text of each `requestJira`, `requestConfluence`
and `requestBitbucket` call (`definitions/authz_request.rs`, `request.rs`). Inline literals are
read from the AST and `const` bindings are followed. A spread, a computed key, an accessor,
`__proto__`, a method that is not a string literal, a `let` or `var` binding and a call with
more than two arguments are unknown, and a rule needs a proven fact: an unknown method or route
keeps the finding. A request that names no method is a GET.

## Instance metadata (`instance-metadata-route`)

A proven GET whose route matches an entry of the table in `checkers/authz_routes.rs` is not
reported. These routes return site configuration that is the same for every viewer and that
every user already sees in create and edit forms and pickers:

* fields and issue types, and issue create metadata;
* workflow vocabulary: statuses, status categories, priorities, resolutions, issue link types,
  labels, project roles, workflow search and workflow scheme lookups;
* screens, screen schemes and issue type screen schemes, field configuration schemes and
  field-context mappings;
* site settings and query vocabulary: server info, configuration, time tracking options, JQL
  autocomplete data, attachment settings;
* site-level lookups: the id of the Assets workspace, the license state of an app, the app's own
  JQL function precomputations;
* `myself`: the user the app acts as, not a user of the caller;
* lists of containers: projects, boards, service desks and spaces, and one service desk by id.

Patterns are anchored on path segments. `:v` is the REST version (`2`, `3` or `latest`), `{}`
is exactly one segment, other segments match literally without regard to case, and the query
string is ignored. `/rest/api/3/field` does not match `/rest/api/3/field/search/extra` or
`/rest/api/3/fieldx`, and a segment whose text is computed matches no literal segment. Routes
that name a resource (an issue, a project, a project's roles, a search, a page, an attachment, a
board's configuration, a property) are not in the table.

Accepted risk: the lists of containers name projects, boards, service desks and spaces that the
caller may not be allowed to browse, and the rule does not report them. It was accepted because
the triage of the scanned corpus found one true positive that depends on it.

Not covered: a request whose method is not a proven GET, a route that is not a literal or a
`const` binding of one, and every route not in the table. Anything the rule does not decide is
reported as before.
