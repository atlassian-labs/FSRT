Minimized from `setMonotonicNotificationRecord` in `claude-agent-forge-app`.

Run from the FSRT repository root:

```sh
cargo run -p fsrt -- --scanners secret test-apps/object-alias-cycle
```

Repeated calls with different object arguments create a multi-variable alias
cycle while the interpreter copies argument values into `save`. Before the fix,
`Interp::get_farthest_obj` follows that cycle indefinitely. The extra read of
`record` and the empty `read` resolver preserve the lowering and traversal that
trigger the bug; retain them in this regression fixture.

`cargo nextest run -E 'test(object_alias)'` runs this fixture and the direct
interpreter tests with a five-second termination timeout.
