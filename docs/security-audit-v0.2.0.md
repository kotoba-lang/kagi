# v0.2.0 security review delta

Status: ready for independent review; external audit not yet performed.

Review `kagi.recovery` for GF(256) arithmetic, coefficient generation, Lagrange
interpolation, share-set binding and integrity validation. Review `kagi.sync` for the
optimistic sequence gate and confirm that transport/auth failures can no longer be treated
as an empty remote followed by push.

Focused evidence:

```bash
clojure -M:test -n kagi.recovery-test
clojure -M:test -n kagi.sync-test
clojure -M:test
clojure -M:lint
```

Known limitation: v0.2.0 exposes the threshold primitive to library consumers; a hardened
operator ceremony for generating, printing, storing and consuming shares remains future CLI work.
