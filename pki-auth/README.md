# s2-pki-auth

PKI v2 combines P-256 RFC 9421 HTTP Message Signatures with issuer-signed
Biscuit capabilities. PKI mode replaces access tokens: neither the SDK nor
Lite consults a bearer provider, an OAuth session, or a token permission table.
The public repository contains the Lite server; a hosted server can call the
same verification functions at its request and mutation boundaries.

## Grants and delegation

`issue_grant` signs the authority block with the issuer key. Its v2 claims bind
one client public key, one HTTP origin, basin and stream resource scopes,
operation IDs from `s2_common::access::Operation`, and an absolute expiry.

`delegate_grant` requires the current holder's private key. Alice signs a
Biscuit third-party block bound to the preceding block signature; that block
can bind Bob's key. Bob signs subsequent HTTP requests. Every hop must preserve
the audience and narrow both resource scopes, operation permissions, and
expiry. `restrict_grant` performs the same signed operation while retaining the
holder. Ordinary unsigned Biscuit attenuation blocks are rejected by this
profile. New clients and grants are required; the earlier fork's tokens are
not v2 credentials.

`verify_biscuit` verifies the issuer and every delegation. `verify_request`
additionally verifies the leaf client's HTTP proof and returns a
`VerifiedRequest`. `authorize_operation` and `authorize_append` evaluate the
verified capability without a database. All Biscuit checks also execute against
trusted request facts (`time` as Unix seconds, `operation` as its Rust variant
name, and decoded `basin`/`stream` strings). Fact construction uses typed values.
The host must consume the nonce atomically and check every revocation identifier
before accepting a request. Neither of those state checks can grant permissions.

Revocation is `POST /v1/pki/revocations` with `{"grant":"<Biscuit base64url>"}`.
Only the issuer or a holder in that grant's ancestry may revoke it. The target's
last block identifier is persisted, and descendants containing that identifier
are denied. Revoking the root invalidates its entire delegation tree.
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

Streaming requests sign their opening and rely on authenticated TLS for frames.
Use TLS directly or a trusted TLS terminator that preserves the original
external host, path, query, and signed headers. Cleartext streaming is limited
to loopback development. This profile does not authenticate individual frames
through an untrusted TLS terminator. Sessions last at most five minutes or the
grant expiry, whichever comes first, and Lite rechecks revocation and expiry
at least once a second, including idle sessions. Every append batch checks
Append and any Trim/Fence commands before submission. SDK retries and reconnects
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

A scope file, for example `scope.json`, uses the shared operation IDs:

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
s2 lite --tls-cert cert.pem --tls-key key.pem \
  --pki-issuer "$(cat issuer.pub)" --pki-audience https://streams.example.com
```

Key generation and grant output create new private files without overwriting
existing files. Credential selection stores the key and grant in the OS
credential store; `--insecure-storage` explicitly selects the existing private
credential-file backend. The ordinary config contains only the store reference.
PKI selection ignores `S2_ACCESS_TOKEN`, binds both CLI endpoints to the grant
origin, and fails if they are later changed. `s2 auth use pki` reselects saved
credentials; `s2 auth pki remove` removes them.
