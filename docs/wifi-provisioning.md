# Account Wi-Fi provisioning

kagitaba.wifi defines an encrypted wireless-router item. SSID, password and
account principal are concealed fields; all fields including security are sealed
as one payload by the existing kagi.operation actor. The public graph has only
its normal opaque item ID, category, version, encrypted block reference and
wrapped keys. SSIDs are not identifiers or public titles.

kagi.wifi/create-request produces the existing :item/create operation. Run it
through the normal actor/Governor with an authenticated owner context, VMK,
purpose, restricted clearance and audit signer. Clearance must come from trusted
policy attributes, never from the caller or a client boolean. kagi.wifi/reveal-request uses restricted classification;
set the context purpose to :wifi-provision and run the same governed actor.
transfer-network accepts a completed reveal only after the trusted host verifies
principal binding, matches the physical Node, and receives explicit user consent
within the expiring session. Encrypt this one network with the transport's fresh
Node/session key. Never transfer the VMK, PRF output, DEK or whole vault. Signing
in does not grant permission to transfer a network.

choices always offers manual entry, and offers saved profiles only when account
authentication, vault unlock and storage retrieval succeeded. PRF absence in a
hybrid passkey ceremony must not become plaintext storage or a second account;
use an existing approved kagi unlock mechanism or manual entry.

These are portable model/request/consent helpers, not a deployed account vault
service. A production host must still resolve verified account -> vault identity,
unlock the existing VMK, execute the governed operations, bind a ciphertext-only
SealedBlockStore plus metadata backend, and verify retrieval on an independent
replica. A MemoryStore fixture or an IPFS adapter declaration is not distributed
persistence evidence. Deleting a profile revokes access/future transfer; encrypted
blocks already replicated may remain, and a Node already given a password must
have its local connection removed or the Wi-Fi password rotated separately.

Plaintext create requests/reveal results also pass through the actor state. Use
an ephemeral checkpoint for these operations; any durable checkpoint requires
its own encrypted store and the same secret handling policy. Do not serialize
plaintext actor state into a public/distributed checkpoint or an agent log.

Runtime test (after npm install):
`kbb --backend sci --config nbb.edn --classpath src:test test/kagi/wifi_runtime.cljk`.
The pinned kagitaba commit is reachable. The test uses the real noble crypto and
kagi actor/Governor but an in-memory backend. It verifies encryption/reveal,
secret-free graph metadata/ledger, foreign-account/Node/expiry/consent refusal,
viewer refusal and manual fallback while the vault is locked.

## Replica read-back boundary (2026-10-07)

`kagi.wifi-replica/replicate!` sends an already sealed block to configured host
providers and reads each reference back before issuing a receipt. A trusted host
SHA256 digest verifies content and length. `object-key` accepts only hashed
account/item identifiers. Receipts contain no plaintext or vault keys. The host
must store these receipts inside the account vault, and provide versioned,
immutable object writes or IPFS content references. Provider credentials stay in
the host and must never be returned to the companion view.

Distinct origins prevent accidental duplicate adapter configuration; they do
not establish independent operators or physical replicas. `verified-readbacks`
is the number of successful retrievals, not a decentralization claim. A real
qualification must record the configured operators and repeat retrieval from a
fresh process after restart.

The fixture runtime verifies read-back and refuses corrupt bytes:
`kbb --backend sci --config nbb.edn --classpath src:test test/kagi/wifi_replica_runtime.cljk`.
This is not a live storage connection. Current Mac inspection found no configured
storage environment variables or the documented Keychain service
`b2:com-junkawasaki-kagi`. The existing vault could not be loaded by the current
read-only SCI seam; it was not modified or migrated. Production endpoint,
credentials and verified account-to-vault binding remain required.

## Production connection investigation follow-up

The previous local SCI load failure was traced to the generic EDN 8MiB whole
input cap. The existing local vault is larger. Node `persist/load*` now checks
file size before reading and uses a scoped synchronous 32MiB whole-file cap;
string/token/depth/node/tag bounds remain unchanged, as does the generic network
EDN cap. Reading the existing vault and Keychain unlock succeeded. No vault
migration, write or key change was performed.

The documented `com-junkawasaki-kagi-b2` item was absent. Narrow storage-related
metadata lookup found only archive-encryption master-key entries, which are not
storage transport credentials and are not used for Murakumo Wi-Fi. Production
account identity, account-to-vault binding and a configured endpoint credential
reference are still required. Do not substitute an archive key or silently bind
all authenticated accounts to the operator's local vault.
