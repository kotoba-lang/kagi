# Native kagi v1

The foundation below records the original public-verifier/core contract.
The 2026-10-24 [native local host candidate](native-local-host.md) adds the
separate private host/journal entry and bounded role-purpose sets. Production
custody and the foundation artifact lock are not silently promoted by it.

Owner decision 2026-10-23: native Kotoba / Amu selfhost only; no old-key,
vault-format compatibility or migration. This supersedes the hosted
providers and old-vault acceptance criteria in ADR 0002. Existing user
key data is outside this change. `src/`, `sdk/` and old test sources are
unsupported inventory, not an alternate native implementation.

## Authority and current qualification

The pure core verifies public keyset proofs and delegated signing policy.
The native CLI exposes `status`, `help`, and offline `verify-keyset` only.
It never reads `~/.kagi` or accepts legacy import/get commands. `bin/kagi`
points directly to `target/native/kagi`; an absent artifact cannot start.
The selected executable is a loaderless arm64 Linux ELF, not a macOS binary.

App, browser and LLM input must not become the trusted genesis, current
keyset state, clock, replay sequence, writer fence, parent head or seed.
The host derives public state from proofs anchored at an independently
trusted genesis. `kg-state-problem` validates shape, not trust or freshness.
An application-supplied state string must never be admitted as verified.

`kg-sign` is a pure component API. It returns a signature only after checking
policy, delegate, purpose, scope, audience, TTL, sequence, parent, fence,
keyset head and epoch. A trusted host must commit durable replay/audit state
before returning a signature to an application. That host is not implemented
by this CLI. No signing oracle, custody/keygen command or remote endpoint
is exposed by this foundation.

Node keys authorize node declarations/heartbeats. Agent keys authorize Cell
actions/state commits. Neither grants another person's funds, workspace or
node resources. Browser operation consent and bot `yakuwari.edn` remain
independent ceilings. A software signer under the same host administrator
trusts that administrator; it is not independent hardware custody.

## Canonical public formats

All fields are ASCII, separated by one space. No leading/trailing space,
duplicate spaces or embedded newlines. A line is at most 4096 characters.
Numbers are canonical nonnegative decimal, at most 15 digits, with no
leading zero except `0`. Hex is lowercase and has the exact stated length.
Labels use `[a-z0-9:._-]`, length 1..128. Digest identifiers below are
SHA-256 values, **not IPLD CIDs**. Scope is an exact opaque policy label;
mon/CID admission is a separate upper-layer gate.

```
kagi.keyset.event.v1 OP EPOCH PARENT AUTHOR POLICY GUARDIANS THRESHOLD
kagi.keyset.state.v1 GENESIS HEAD EPOCH STATUS AUTHOR POLICY GUARDIANS THRESHOLD
kagi.agent.policy.v1 ROLE SCOPE AUDIENCE DELEGATE PURPOSE MAX_TTL_MS
kagi.agent.permit.v1 KEYSET HEAD EPOCH PURPOSE SCOPE AUDIENCE BODY PARENT FENCE SEQUENCE ISSUED_MS EXPIRES_MS
```

`AUTHOR` and `DELEGATE` are 64-hex Ed25519 public keys. Digest fields are
64 hex. `GUARDIANS` is three concatenated 64-hex public-key slots; zero means
unused. Active guardians must be distinct; threshold is 1..active count.
Management proof is three concatenated 128-hex signature slots, with zero
for absent signatures. Every supplied signature must verify; valid slot
count must meet threshold. This is individual multisignature validation,
not secret sharing or threshold cryptography.

| Event | Admission |
|---|---|
| genesis | Empty prior state, epoch 0, zero parent, event digest equals independent genesis pin; new guardians authorize; author proves possession |
| rotate | Active keyset, next epoch/parent, prior guardians authorize; different new author proves possession |
| revoke | Active keyset, next epoch/parent, prior guardians authorize; author/policy/guardians/threshold unchanged |
| recover | Revoked keyset, next epoch/parent, prior guardians authorize; different new author proves possession |
| govern | Next epoch/parent, prior guardians authorize new policy/guardians/threshold; author unchanged; revoked status stays revoked |

Management signs `kagi.keyset.manage.v1\n` followed by the exact event.
Author possession signs `kagi.keyset.author.v1\n` followed by that event.
For revoke/govern the possession proof must be the all-zero signature slot.
Historical author keys and old Cell histories are never rewritten.

Policy role `agent` permits one of `cell-action`, `state-commit`; role
`node` permits one of `node-declaration`, `node-heartbeat`. Each policy has
one exact scope, audience, delegate and purpose. No wildcard or delegation
chain is admitted. TTL is 1..60000 ms; policy digest must match verified
keyset state. The delegate signs the exact permit line. The author signs
`kagi.agent.action.v1\n` followed by that permit. The author seed must derive
the verified current author public key. Epoch/head mismatch, revoked state,
bad delegation, expired/future permit, wrong parent/fence or sequence other
than `lastSequence + 1` is refused. Trusted sequence starts at 0.

The last wall-clock reading / replay state must survive restarts in the
host journal; a kernel clock alone does not prevent wall-clock rollback.
Freshness/fork resolution of distributed keyset heads remains JUN-300.
Historical proof validation does not establish permission for a new write.

## Offline bundle verification

`verify-keyset GENESIS FILE` accepts a public LF-delimited file, at most
262144 characters / 64 events. Each record contains the exact event's
eight fields, management signature slots and author proof (ten fields).
No state snapshot or self-declared trust root is accepted from that file.
The trusted genesis pin is a separate operator/installer argument.

Output is the derived public state on stdout, exit 0. Refusals are named on
stderr, exit 2. Public fixtures use **published RFC 8032 seeds** and must
never become operational keys. The CLI does not acquire distribution
freshness, enroll a node, run a Cell or connect to a service.

## Native build path

The component was built with Amu combined selfhost root revision
`11630662`, artifact SHA-256
`61ee2d3870612c7f8ed6bd2d25f40c8cc68b26d2b5b5336204b1ff2651fe60bb`.
No JVM, Node/NBB/KBB, C compiler or C runtime/loader participates in source
assembly, compilation or execution of the final candidate.

Pinned source owners:

| Repository / source | Revision | SHA-256 |
|---|---|---|
| org-nist-sha2 `kotoba/sha2/core.kotoba` | ea83e70a6a8efb8fb12dd5f0031fcda35a9ec77b | 2c59ef55bc2b527c1aac723c0fee896eba75ee82fecd212a2858782beadc6888 |
| org-ietf-ed25519 `kotoba/ed25519/selfhost.kotoba` | 6f17477b5be91a0c8c369b8d30e7e5ea0c10a8aa | 47c086f3d93ad4f6da047bbf3b9250f7e4fbc7539ec1a0077abb2d82ceb3dc14 |

On arm64 Linux, using explicit granted paths and the verified compiler as
`/compiler`, the native steps are:

```sh
/compiler compile /repo/kotoba/kagi/assemble.kotoba --target aarch64-linux --output /build/assemble --format static
chmod 755 /build/assemble
/build/assemble cli /owners/sha2.kotoba /owners/ed25519.kotoba /repo /build/cli.kotoba
/compiler compile /build/cli.kotoba --target aarch64-linux --output /build/kagi --format static
```

Compiler grants: wire 35 for `/repo:/build`, stack 8388608.
Assembler grants: wires 3,35,37,38,39; wire 35 roots
`/owners:/repo:/build`. It verifies both owner source digests before
removing their pinned namespace headers and concatenating the component.
Mode `gate` assembles the native tests instead. It refuses existing output
under its single-writer build workspace and rejects changed owner source.
This is a bounded explicit component assembler, not a general project
linker, installer or qualified CDCI controller. Supply the executable bit
and verify artifact digest before installation; no automatic download or
native-target fallback is provided.

The final CLI artifact SHA-256 is
`a89f56d731585363b93bd9502a1a107b9b9578763db35fbf7f5de14227f706ba`.
The new native assembler reproduces the earlier diagnostic assembly's
CLI artifact byte-for-byte. Initial fixture generation used OpenSSL 3.6.4
as an independent public-test oracle; diagnostic Python inspection is not
part of this final native build path or CDCI qualification.

## Gates and remaining work

See `evidence/native-agent-signers-20261023.json` for source and artifact
pins. The native signer gate passed 28/28. Removing management validation
produced 25/28; removing delegate validation or replay validation each
produced 27/28. Independent OpenSSL signatures match. CLI success derives
genesis → rotate → revoke → recover; insufficient management proof,
replayed transition, malformed/empty bundle and legacy commands refuse.

Native entropy/clock replacement is [Amu PR #1518](https://github.com/kotoba-lang/amu/pull/1518),
tracked under AWAI-52. It passes native arm64 provider / refusal gates, combined
self-rebuild fixed points and 24 runtime regressions, but is not an adopted root.
Existing generic native file writes create mode 0644; do not
use them to persist new private seeds. Private create/owner/mode checks,
durable replay/audit commits, secret memory erasure, side-channel and full
public-point admission qualification remain open. The pinned Ed25519
library's signing API is not qualified as constant-time custody on a shared
host; the core's zero/identity checks are not a full subgroup-admission
claim. Therefore no production signing/key generation is enabled.

Signed node wire adapters, hata's whole Cell runtime, persistent duplex
stdio, verified distributed heads, Yataverse restoration and actual UI
control follow those foundations. A generic signed permit is not yet a
tsukasa declaration or kotobase commit signature.
