# s2-pki-auth

PKI v2 combines P-256 RFC 9421 HTTP Message Signatures with issuer-signed
Biscuit capabilities. PKI mode replaces access tokens: neither the SDK nor
Lite consults a bearer provider, an OAuth session, or a token permission table.
The public repository contains the Lite server; a hosted server can call the
same verification functions at its request and mutation boundaries.

## Grants and delegation

`issue_grant` signs the authority block with the issuer key. Permissions and
scope are native Biscuit Datalog facts and checks, with no embedded JSON payload.
Every block has a zero-based index. An authority block for reading streams under
`events/` in basin `logs` contains these facts (the holder key is abbreviated):

```datalog
pki_version(0, 2);
pki_holder(0, "<Alice's compressed P-256 public key in Base58>");
pki_audience(0, "https://streams.example.com");
pki_expires(0, 2000000000);
pki_basin(0, "exact", "logs");
pki_stream(0, "prefix", "events/");
pki_operation(0, "Read");

check if operation($op), pki_operation(0, $op) trusting authority;
check if audience($a), pki_audience(0, $a) trusting authority;
check if time($now), pki_expires(0, $expiry), $now < $expiry trusting authority;
check if basin_present(false) trusting authority
    or basin($b), pki_basin(0, "any", "") trusting authority
    or basin($b), pki_basin(0, "exact", $b) trusting authority
    or basin($b), pki_basin(0, "prefix", $p), $b.starts_with($p) trusting authority;
check if stream_present(false) trusting authority
    or stream($s), pki_stream(0, "any", "") trusting authority
    or stream($s), pki_stream(0, "exact", $s) trusting authority
    or stream($s), pki_stream(0, "prefix", $p), $s.starts_with($p) trusting authority;
```

The authorizer supplies the operation, HTTP audience, Unix time, and decoded
resource names. Presence flags describe that request's resource context; the
host rejects missing resources for operations that require them. The allow
policy reads only authority permissions:

```datalog
allow if operation($op), pki_operation(0, $op) trusting authority;
```

Biscuit must satisfy every block's checks before that policy can allow a request.
Resource kinds are `none`, `any`, `exact`, and `prefix`; `none`/`any` have an empty
value. Operation names match `s2_common::access::Operation` variants, excluding
access-token management. The profile validates literal metadata and mandatory
checks in each signed block, rejects duplicate metadata and facts for another
block index, and prevents token facts or rule heads from defining the server's
request predicates or deriving `pki_*` metadata. Mandatory checks explicitly
trust authority, their own block, and authorizer facts; later blocks cannot
change an earlier check's inputs, including when the same holder signs twice.

`delegate_grant` requires the current holder's private key. Alice signs a
Biscuit third-party block bound to the preceding block signature; that block
can bind Bob's key. A delegation contains the same native facts/checks at its
new block index, plus `pki_parent(index, hex:<previous block identifier>)`.
Bob signs subsequent HTTP requests. Every hop must preserve
the audience and narrow both resource scopes, operation permissions, and
expiry. `restrict_grant` performs the same signed operation while retaining the
holder. Ordinary unsigned Biscuit attenuation blocks are rejected by this
profile. New clients and grants are required; the earlier fork's tokens are
not v2 credentials.

`verify_biscuit` verifies the issuer and every delegation. `verify_request`
additionally verifies the leaf client's HTTP proof and returns a
`VerifiedRequest`. `authorize_operation` and `authorize_append` evaluate the
verified capability using Biscuit's authorizer, without a database or a parallel
Rust permission evaluator. Additional Biscuit checks run alongside the required
native checks, under a conservative admission budget enforced by the shared
crate before any policy evaluation. There are at most 512 literal facts across
the token, 64 custom queries, and 4096 aggregate custom work units. Each custom
query has at most one body predicate and 16 expression operations; its work
charge is `(literal facts + 7 ambient facts) * (1 + predicate arity + expression
operations)`, or one candidate for a predicate-free query. Scalars are bounded
to 1024 bytes, names to 128 bytes, and predicates to eight terms. The five exact
mandatory native checks occur once per block; their singleton/indexed joins
have fixed cost. Custom rules/fact generation, multi-predicate custom joins,
collections, closures, regex, and expanding operators are rejected. Scalar
comparisons, booleans, length/type queries, and prefix/suffix checks remain
native, including One/All/Reject checks and OR alternatives within the budget.
Biscuit's 100 ms cooperative timeout is secondary; it is not relied on to
interrupt a query or rule expansion. Public-key trust scopes are rejected in
every block's global scopes, rules, and check queries: Biscuit resolves such scopes across future
blocks, which could relax an ancestor's custom restriction. Custom checks may
use the default authority/current origins or `trusting previous`; those origins
are fixed to the signed prefix. Fact construction uses typed values, so resource
names are never interpolated into Datalog source.
Stream provisioning performs a shared-crate preflight before reading metadata.
An ensure requires at least one of CreateStream/ReconfigureStream initially,
then the actual operation is checked after determining existence. Forbidden
requests cannot disclose whether the basin is absent, present, or deleting.
For listings, `authorize_collection` evaluates native operation, expiry,
audience, and known-basin checks first; the host must then call
`authorize_operation` with each candidate's
resource facts before exposing it or counting it toward pagination. A resource
check can therefore produce an empty allowed result without blocking the list.
The host must consume the nonce atomically and check every revocation identifier
before accepting a request. `VerifiedRequest::validate_admission` must pass
both before replay-state work and after durable nonce consumption, immediately
before invoking a handler. A proof that expires during awaited work is denied;
an already admitted session continues under its separate lease. Nonce cleanup
reads the current nonce expiry in its serializable deletion transaction and
only removes a value matching the expired index, preserving replacements and
skipping conflicting cleanup transactions. Neither state check grants permissions.

Revocation is `POST /v1/pki/revocations` with `{"grant":"<Biscuit base64url>"}`.
Only the issuer or a holder in that grant's ancestry may revoke it. The target's
last block identifier is persisted, and descendants containing that identifier
are denied. S2 identifiers canonicalize every P-256 internal block signature to
low-S DER and retain Ed25519 signature bytes. This makes revocation stable across
equivalent ECDSA signature representations. `pki_parent` contains that canonical
identifier; Biscuit still verifies its cryptographic chain using the original
signed bytes. Revoking the root invalidates its entire delegation tree.
Self-revocation completes its durable acknowledgement after removing authority.

## HTTP and streaming

The signature covers `@method`, the complete `@target-uri` including its query,
`Authorization: Biscuit …`, a signed `s2-pki-body` mode, every present `s2-*`
header, and present content type/encoding/digest, idempotency, range, accept,
conditional, and SSE replay-cursor headers. The v2 profile uses one canonical
`s2` signature with P-256, tag `s2-pki-v2`, a 32-byte random nonce, creation time,
and expiry within 60 seconds. Unary requests always include a SHA-256
Content-Digest, even for an empty body, calculated after compression. Lite
verifies bytes before decompression and does not trust forwarded origin headers.

Streaming requests sign their opening; individual frames are not covered by
that HTTP signature. Sessions last at most five minutes or the
grant expiry, whichever comes first, and Lite rechecks revocation and expiry
at least once a second, including idle sessions. Reads also re-evaluate all
Biscuit checks against the current time and effective basin/stream before
releasing data. Every append batch checks
Append and any Trim/Fence commands before submission. PKI append sessions defer
implicit creation until the first batch passes those checks; rejected unary or
first streaming batches leave the resource absent. Automatic creation requires
CreateStream alongside the data operation, with no extra GetBasinConfig grant.
SDK retries and reconnects
sign fresh proofs; append uncertainty monitoring remains active.

Lite stores nonce and revocation state in SlateDB using reserved prefixes
`0xf0`, `0xf1`, and `0xf2`. Nonces are atomically consumed and durably committed;
a bounded expiry-index sweep removes expired nonce rows on subsequent requests.
Revocations are durable. There is no database-backed permission lookup.

## SDK

```rust,no_run
use s2_sdk::{S2, pki::{ClientKey, ClientPublicKey, Grant, PkiCredentials},
             types::{S2Config, S2Endpoints}};
# fn example(private_key: &str, biscuit: &str, issuer: &str) -> Result<(), Box<dyn std::error::Error>> {
let key = ClientKey::from_base58(private_key)?;
let grant = Grant::from_base64(biscuit, ClientPublicKey::from_base58(issuer)?)?;
let credentials = PkiCredentials::new(key, grant)?;
let s2 = S2::new(S2Config::new_pki(credentials)
    .with_endpoints(S2Endpoints::for_endpoint("https://streams.example.com")?))?;
# Ok(()) }
```

Ordinary access-token management methods fail locally in PKI mode. Existing
bearer and OAuth behavior remains available when PKI is not selected.

## CLI and Lite

Generate an issuer key and a client key:

```sh
s2 auth pki keygen --private-key-file issuer.key --public-key-file issuer.pub
s2 auth pki keygen --private-key-file alice.key --public-key-file alice.pub
```

The CLI accepts a convenience scope file, for example `scope.json`, using the
shared operation IDs. This is issuance input; it is converted to native facts and
checks before signing and is never serialized into the Biscuit:

```json
{"basins":{"Exact":"my-basin"},"streams":{"Prefix":"events/"},"operations":[9,14,15,16]}
```

Here 9 is ListStreams, 14 CheckTail, 15 Append, and 16 Read. Scope variants are
`"Any"`, `"None"`, `{"Exact":"name"}`, and `{"Prefix":"prefix"}`.
IDs 6–8 (ordinary token management) are rejected. CreateStream is 10, Trim 17,
and Fence 18; these require explicit grants.

```sh
s2 auth pki issue --issuer-key-file issuer.key --client-key "$(cat alice.pub)" \
  --audience https://streams.example.com --scope-file scope.json \
  --expires-at 2000000000 --out alice.grant.json
s2 auth pki set --key-file alice.key --grant-file alice.grant.json
s2 auth status
s2 auth pki delegate --key-file alice.key --grant-file alice.grant.json \
  --client-key "$(cat bob.pub)" --scope-file narrower-scope.json \
  --expires-at 1999999000 --out bob.grant.json
s2 auth pki inspect --grant-file bob.grant.json
s2 auth pki revoke --grant-file bob.grant.json
S2LITE_PKI_ISSUER="$(cat issuer.pub)" \
S2LITE_PKI_AUDIENCE=https://streams.example.com s2 lite
```

Lite accepts the trusted root public key through `S2LITE_PKI_ISSUER` (or
`--pki-issuer`), with optional comma-separated roots for rotation. Set the exact
HTTP grant origin in `S2LITE_PKI_AUDIENCE` (or `--pki-audience`), formatted as
`scheme://host[:port]` with no trailing slash. Providing one
without the other, an invalid root key, or an invalid origin fails startup
before storage initialization. A complete pair activates exclusive PKI
verification for the API; grant files and request headers cannot select trusted
roots. The existing non-PKI mode is selected only when neither setting is present.

`s2 auth pki inspect` includes each signed block's native source in
`datalog_blocks`, alongside its verified delegation metadata. The `.grant.json`
file is an outer transport wrapper containing the issuer key and base64url
Biscuit, rather than a JSON authorization payload inside the token.

Key generation and grant output create new private files without overwriting
existing files. Credential selection stores the key and grant in the OS
credential store; `--insecure-storage` explicitly selects the existing private
credential-file backend. The ordinary config contains only the store reference.
PKI selection ignores `S2_ACCESS_TOKEN`, binds both CLI endpoints to the grant
origin, and fails if they are later changed. `s2 auth use pki` reselects saved
credentials; `s2 auth pki remove` removes them.
