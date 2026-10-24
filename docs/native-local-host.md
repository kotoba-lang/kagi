# Native local-software signer host

JUN-299. `kotoba/kagi/host.kotoba` connects the native core to clock,
entropy, private storage and a replay/audit journal. This is a **local
software custody candidate**: the same administrator controls the author,
delegate and guardian files. Its status always reports
`independentCustody=false` and `productionQualified=false`.

Existing keys, vaults and profile stores are not read or migrated. New
qualification fixtures stay outside repositories and release archives.
Production custody/guardian placement requires the operator's separate
configuration; a locally generated guardian does not establish independence.

## Commands

Use the verified native `kagi-host` artifact, not the old hosted helpers.
The selected target is arm64 Linux, including the Mac's Linux VM. An absent
or unsupported provider fails closed; there is no JVM/Node/old-key fallback.

```text
init-local PRIVATE_ROOT agent|node SCOPE AUDIENCE PURPOSE MAX_TTL_MS
status-local PRIVATE_ROOT
export-local PRIVATE_ROOT
audit-local PRIVATE_ROOT
permit-local PRIVATE_ROOT BODY_FILE [PURPOSE]
sign-local PRIVATE_ROOT REQUEST_FILE BODY_FILE
sign-local-line PRIVATE_ROOT REQUEST_FILE BODY_FILE
watch-local PRIVATE_ROOT PUBLIC_DIRECTORY SAMPLES_1_TO_720
```

The operator creates a new, owner-only 0700 root. Init draws three independent
32-byte seeds from the native entropy provider, proves the author, and signs
the keyset genesis. Exclusive private creates write author, guardian,
delegate, policy, public proof bundle and journal. Config is published last;
a partial initialization is refused on retry instead of overwriting files.
Routine author signing does not read the guardian or delegate seed.
`permit-local` is a trusted local delegator command, not a browser endpoint.

`export-local` emits only the public config/policy/keyset proofs. A consumer
must pin genesis and expected head independently, not trust the export's
own declaration. `sign-local-line` emits permit + delegate signature + author
signature on one LF-terminated line, for native protocol adapters. The JSON
variant additionally reports the journal head. Neither exports a seed.

Each signing operation verifies the complete proof and journal, current
policy/head/epoch, exact role/scope/audience, delegate signature, body digest,
sequence, parent, writer fence and deadline. It reads the native clock and
refuses wall-clock rollback. It rechecks time after cryptographic work and
after commit. The author signature is released only after a successful
private compare/append/fsync. A concurrent request, expired reply or failed
commit releases no signature. A committed operation whose reply is lost
still consumes its sequence; inspect `audit-local`, never blindly retry.

Journal records include the permit, delegate and author signatures, trusted
wall reading and prior-record hash. Startup verifies every record and its
link; truncated, altered, public-mode or unverified history does not become
an empty journal. Parent advances to the previous operation's body digest.
Keyset rotation/recovery has no automatic operational command in this host;
the pure verifier continues to validate those transitions separately.

Policies may select an individual purpose or one of two explicit bounded
sets: `node-statements` permits only node-declaration/node-heartbeat;
`cell-writes` permits only cell-action/state-commit. The set label itself is
not an action purpose. Neither set crosses roles, grants arbitrary signing,
delegates further, or changes the exact scope/audience.

## Read-only Mac status

Watch revalidates proof/journal state, writes `signer-status.json` to a
separate public directory through temp/fsync/rename/dir-fsync, then sleeps
five seconds. It runs at most the supplied sample count. A failed proof or
publication stops the process; old snapshots become stale in the UI.

The Mac watcher mounts only config, policy, public bundle and journal as
read-only files in a 0700 directory. **No seed is mounted.** Its only writable
mount is the public snapshot directory. The static UI origin never serves
that directory; the user chooses the files locally. The browser treats them
as observations, not cryptographic authorization or browser-operation consent.

## Build and limits

Native assembler mode `host` combines the exact pinned SHA-256/Ed25519
owners, core, CLI proof reader and host. Modes `cli` and `gate` remain.
The host needs the Amu KPV1 provider candidate; the foundation compiler in
`native.lock.json` is historical for this new host and cannot supply it.
Build evidence pins the exact source graph, selfhost root and artifacts.

The 32-case core gate and replay mutation are separate from host lifecycle,
concurrent signing, metadata/refusal, node adapter and UI gates. Source
assembly is a bounded component builder, not a general project linker or
native public installer/CDCI controller. Secret-memory, constant-time,
hardware/independent custody and distributed head freshness remain open.
Do not promote local enrollment or an OCI process to hata Cell execution.


## Local-only qualification, 2026-10-24

The owner selected validation on this Mac only; independent production
custody and guardian placement are deferred. The separate host lock is
[`native-local-host.lock.json`](../native-local-host.lock.json). Receipts
record 16 node-host lifecycle cases and 7 agent/bot isolation cases. Agent
and bot roots generate distinct identities, reject each other's permits,
and maintain independent sequences. A `cell-action` / `state-commit`
signature here does not execute a Cell or commit a distributed state DAG.

With the pinned executable on arm64 Linux, run each diagnostic into a new
private fixture directory:

```text
python3 test/native/host_gate.py --artifact /verified/kagi-host --output /new/node-fixtures
python3 test/native/agent_host_gate.py --artifact /verified/kagi-host --output /new/agent-fixtures
```

These output directories contain new private keys; keep them outside Git,
static hosting and release artifacts. Only public JSON receipts belong in
the evidence record. The public Mac watcher uses a separate retained local
qualification profile and does not regenerate its keys when restarted.
