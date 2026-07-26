# E2EE

> End-to-end encryption primitives for pilot→airport submissions: envelope encryption, key directory, offline trust root

**Status: proposal.** Nothing here is implemented. This document exists to pin
down the trust model and wire format *before* any code, because both are
expensive to change once real submissions exist.

## Intent

Let a pilot submit passenger identity data to an airport through a flyfun
server that **cannot read it**. The server routes, schedules, notifies and
reports; it never holds a key that opens the identity payload.

This is the shared crypto layer. The submission lifecycle, airport console and
product decisions live in
[flyfun-forms/designs/submission-server.md](../../flyfun-forms/designs/submission-server.md).

### Why this lives in flyfun-common

`flyfun-common` already owns identity: `users`, `api_tokens`, magic-link
sign-in, cross-subdomain SSO on `.flyfun.aero`. Key material is identity
material. Putting it anywhere else means two services race to own "who is this
principal and what key proves it."

Note that `flyfun_common.encryption` (Fernet, `CREDENTIAL_ENCRYPTION_KEY`) is
**not** this. That module encrypts OAuth credentials with a server-held key —
the server can decrypt by design. It stays as-is for credentials and must never
be used for submission payloads.

## Non-goals

Stating these explicitly, because the obvious mental model ("like Signal") is
misleading in three specific ways:

- **No Double Ratchet.** The ratchet gives forward secrecy across a long-lived
  interactive conversation between two devices. A submission is a one-shot
  message read by an *organisation* and retained for years. A ratchet would
  actively break the requirements: shared-desk state, unreadable history after
  rotation, no second reader.
- **No protection against a malicious server operator in the browser.** If the
  airport console is a web app, the server ships the JS that decrypts. See
  [Threat model](#threat-model) — this is the honest boundary, and it must be
  stated in user-facing privacy copy rather than glossed.
- **No metadata privacy.** Tail number, route and times are deliberately
  cleartext (Tier 0) because the whole product is built on them.

## Threat model

| Adversary | Protected? | Why |
|---|---|---|
| Stolen DB dump / leaked backup | ✅ **Yes** | Ciphertext + wrapped DEKs only. No key on the server. **This is the main prize.** |
| Rogue operator with DB/shell access | ✅ Yes | Same — reading disk yields nothing openable |
| Subpoena served on flyfun | ✅ Yes | We genuinely cannot produce passport numbers. Deliberate. |
| Network attacker / TLS-terminating proxy | ✅ Yes | Payload encrypted beneath TLS |
| Compromised airport officer device | ❌ No | They hold org keys — nothing fixes this |
| Malicious server serving backdoored console JS | ❌ **No** (browser) / ✅ Yes (native) | Web crypto cannot defend against a hostile code source |
| Metadata analysis (who flew where, when) | ❌ No | Tier 0 is cleartext by design |
| Linkage graph ("these visits are one person") | ⚠️ Partial | Server sees opaque blind-index tags, not identities |

The web-console row is the one that gets oversold in products like this. Say it
plainly in `PRIVACY.md`: the encryption defends absolutely against **breach and
compulsion**, and only partially against **us**. A native or desktop airport
client with pinned code closes the remaining gap; a browser cannot.

## Claims we can defend

Security claims are a liability if they outrun the design. A claim that "we
cannot read it" is a **regulatory misstatement**, not merely an embarrassment,
if a bug means we could have. Public copy must derive from the table above, so
it is fixed here rather than left to marketing.

**Say this:**

> We cannot read your passengers' identity data. Neither can anyone who steals
> our database. Only you and the airport you filed with hold the keys, and the
> data is destroyed 30 days after the flight.

Every clause is mechanically true and independently checkable. Supporting
specifics, in descending order of how much they convince a technical reader:

- The server never imports the decryption function — **enforced by an import
  lint in CI**, not by policy.
- Identity fields are shredded on a timer; the ciphertext is inert thereafter
  even in backups.
- The threat model, including its failure rows, is published.
- The crypto layer is open source and independently auditable.

**Never say:** "military-grade encryption" (meaningless, and it marks us as
unserious to exactly the reader we need), "unhackable", "100% secure",
"zero-knowledge" (a specific cryptographic property we do not implement), or
"Signal-level" (invites the browser-console comparison we lose). Never imply
metadata is protected.

Claims should be **versioned and dated**, tied to a specific release, and
accompanied by the limitations. Publishing what we do *not* protect is what
makes the rest credible.

### On AI-assisted attack

Worth stating internally because it is easy to reason about badly: LLMs do not
threaten AES-256 or X25519. Cryptography is not the weak point and never was.
What has genuinely changed is **phishing quality** and **automated discovery of
unpatched exposed systems** — which is the status quo's weak point, not ours.

The consequence for this design is not stronger algorithms. It is that the
**officer's device and session become the target**, since that is where
plaintext exists. Hence phishing-resistant auth (passkeys) for the console, short
retention, per-org key scoping so one compromised airport cannot read another's
submissions, and a bias toward a native client where integrity actually matters.

## Primitives

No novel constructions. All from `cryptography` (Python) / CryptoKit + Secure
Enclave (Swift).

| Purpose | Algorithm | Notes |
|---|---|---|
| Key wrapping | **HPKE** (RFC 9180), DHKEM-X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20-Poly1305 | Base mode. Purpose-built for "encrypt to a public key" |
| Payload | **XChaCha20-Poly1305** (or AES-256-GCM) | Random 32-byte DEK per field group |
| Signing | **Ed25519** | Submissions, approvals, key bundles, tree heads |
| Blind index | **HMAC-SHA256** | Per-airport index key, truncated to 128 bits |
| Canonicalisation | **JCS** (RFC 8785) | Signatures over JSON need a stable byte form |

Rejected: RSA (key size, footguns), NaCl sealed boxes (workable, but HPKE gives
proper AAD binding and a spec both platforms can point at), AES-KW (no
public-key wrapping).

### Post-quantum readiness

Passport numbers, dates and places of birth have a decade-plus shelf life, so
*harvest-now-decrypt-later* against X25519 is a real consideration here in a way
it is not for ephemeral messaging. Not urgent, and adopting a hybrid KEM today
would trade a live compatibility risk for a speculative one — but the wire format
carries `v` and per-group `alg` precisely so a hybrid X25519+ML-KEM HPKE suite
can be introduced later without invalidating existing records. Old generations
stay decryptable under their original suite.

This is also a cheap, honest credibility point with a security-minded reviewer:
the format anticipates the migration rather than claiming immunity.

## Key hierarchy

```
                  FlyFun Root Signing Key (Ed25519)
                  air-gapped / HSM · ships in app binaries
                              │ signs
              ┌───────────────┴───────────────┐
              ▼                               ▼
   Airport Org Signing Key            (pilot keys are self-asserted,
   (Ed25519, long-lived)               TOFU-pinned by the airport)
              │ signs
              ▼
   Airport Org Key Bundle ──────────────────────────────┐
     · org_enc_pub    (X25519)   ← DEK wrapping target  │
     · index_key      (HMAC 32B) ← blind index          │ private half
     · valid_from / valid_until / generation            │ wrapped to
              │                                          each device
              ▼                                          │
   Officer Device Keys (X25519) ◄─────────────────────────┘
     non-extractable · WebCrypto+IndexedDB or Secure Enclave

   Pilot Identity Key (Ed25519)   ── signs submissions
   Pilot Encryption Key (X25519)  ── so the pilot can re-read own history
     both synced via iCloud Keychain (matches existing CloudKit posture)
```

**Wrap to the org, not to officers.** This is the decision that makes staff
rotation survivable. If DEKs were wrapped per-officer, a new hire could not read
anything filed before their start date — fatal for a customs office with
retention duties. Instead DEKs wrap to `org_enc_pub`, and the org *private*
material is wrapped to each authorised device. Onboarding an officer is one
re-wrap and all history opens. Offboarding revokes the device and rotates the
org key forward; anything they could already read, they already read — no scheme
changes that.

## Wire format

Per submission, per **field group** (see
[submission-server.md](../../flyfun-forms/designs/submission-server.md) for the
group definitions):

```jsonc
{
  "v": 1,
  "submission_id": "sub_01J...",     // ULID
  "airport_id": "LSGS",
  "generation": 3,                    // org key generation used
  "groups": {
    "identity_docs": {
      "alg": "XChaCha20-Poly1305",
      "ct": "<base64>",               // AEAD over JCS(group payload)
      "nonce": "<base64>",
      "aad": "v1|sub_01J...|3|LSGS|identity_docs",
      "envelopes": [
        {"kid": "org:LSGS:3",      "enc": "<HPKE encapsulated key>", "ct": "<wrapped DEK>"},
        {"kid": "pilot:u_abc:1",   "enc": "...",                      "ct": "..."}
      ]
    },
    "contact": { /* … different DEK, possibly different recipient set … */ }
  },
  "sig": "<Ed25519 over JCS(v, submission_id, airport_id, generation, tier0, H(groups))>"
}
```

Three details that are cheap now and expensive later:

1. **AAD binds `submission_id ‖ generation ‖ airport_id ‖ group`.** Without it,
   a ciphertext can be silently re-parented onto a different record, or an
   envelope replayed against another airport. Decryption must fail closed on
   mismatch.
2. **Sign the tier-0 metadata alongside the payload hash.** Otherwise the server
   can alter the visible route/times of a validly-signed submission.
3. **One DEK per group, never reused across versions.** An amendment is a new
   version with fresh DEKs, chained by `prev_hash` — not an in-place edit.

### Crypto-shredding

Deleting a submission's envelopes renders its ciphertext permanently inert, even
where an immutable backup still holds the blob. This makes GDPR erasure
genuinely satisfiable across backups — normally a hard problem — and it is the
mechanism behind the short Tier-1 retention window.

## Key directory and trust root

The unsolved problem in schemes like this is never the cipher; it is: **how does
the pilot's app know that key really belongs to customs at LSGS, and not to
whoever runs the server?** A server that hands out airport public keys can
substitute its own and MITM everything, silently.

Options considered:

| Approach | Server can forge a key? | Cost | Verdict |
|---|---|---|---|
| TOFU + pinning + change alerts | Yes, on first contact | Trivial | Necessary, not sufficient |
| Key transparency log (Merkle, CT-style) | Not undetectably | High — log, proofs, auditors, gossip | Later, if ever |
| **Offline root signs each airport bundle** | **No** | Low — one air-gapped signing step per airport | **Chosen** |

Take the offline root. Airports are onboarded one at a time by talking to actual
humans at actual customs offices — a manual, high-touch process that *is* the
out-of-band verification channel. Signal needs a transparency log because it
onboards millions of self-registering strangers; we onboard tens of
organisations over years. Not using that structural advantage would be
throwing away the cheapest strong answer available.

So:

- Root key generated and kept offline (air-gapped machine or HSM); the **public**
  half is compiled into the iOS/macOS app and the console bundle.
- Each airport's key bundle is signed by the root at onboarding time.
- Clients verify the root signature before encrypting to any airport, and
  additionally **pin** the bundle. A changed bundle that still verifies shows an
  explicit "LSGS rotated its keys on <date>" notice rather than silently
  accepting.
- Rotation = new bundle at generation *n+1*, root-signed, with `valid_from`.
  Old generations stay published so historic submissions remain decryptable.
- Revocation = root-signed revocation entry, plus a short-TTL published
  revocation list. Clients refuse bundles whose generation is revoked.

Pilot keys get no root signature — they are self-asserted and TOFU-pinned by the
receiving airport, with a visible change warning. A pilot impersonating another
pilot is a far less interesting attack than a server impersonating a customs
office, and it is caught by the airport recognising an unexpected key change.

## Key recovery

If an airport loses its org private key, its legally-required records become
permanently unreadable. This is the most likely way the system fails in
practice — far likelier than any attack.

- Org private material is wrapped to **several** devices from day one; single-
  device deployment is refused by the onboarding flow.
- A printed recovery code (org private key under a KDF-derived wrap) goes in the
  office safe at onboarding.
- **flyfun must not hold escrow.** If we can recover it, we are not E2EE, the
  subpoena-resistance property evaporates, and we become the attractive target.
  This is a hard architectural line, not a default to be relaxed under support
  pressure.

Pilot-side recovery rides on iCloud Keychain, consistent with the existing
CloudKit private-DB posture in `PRIVACY.md`.

## Blind index

Airports want "when did this passenger last come" — which naively forces
cleartext names. It doesn't.

Each org bundle carries an `index_key`. After decrypting, the **officer's
client** computes:

```
tag = HMAC-SHA256(index_key, normalise(doc_type ‖ doc_number ‖ issuing_country))[:16]
```

and stores the tag back as an opaque value. The server answers "all prior visits
carrying tag X" while knowing only 16 random-looking bytes. Because `index_key`
is per-org, the same passport produces unrelated tags at Sion and in France —
cross-airport correlation is impossible even for us.

Residual leak, to be stated in the privacy doc rather than buried: the server
learns the **linkage graph** — that a set of visits share a subject — without
learning who that subject is.

`normalise()` must be pinned in v1 (uppercase, strip non-alphanumerics, NFKC)
and versioned; changing it silently orphans all existing history.

## Proposed surface

```python
# flyfun_common/crypto/
#   ├── hpke.py        seal_to / open_from
#   ├── envelope.py    seal_groups / open_group  (AAD binding lives here)
#   ├── bundle.py      KeyBundle, verify_bundle, root pubkey pinning
#   ├── signing.py     sign_submission / verify_submission (JCS canonical)
#   └── index.py       blind_index, normalise_document
```

```python
sealed = seal_groups(
    groups={"identity_docs": {...}, "contact": {...}},
    recipients={
        "identity_docs": [airport_bundle.enc_key, pilot_enc_key],
        "contact":       [airport_bundle.enc_key, handler_bundle.enc_key],
    },
    submission_id=sid, airport_id="LSGS", generation=airport_bundle.generation,
)
```

The server calls **only** `verify_submission()` and `verify_bundle()`. It never
imports `envelope.open_group` — enforce that with an import-lint rule so the
property is checked mechanically rather than by discipline.

Swift mirror ships in `Sources/FlyFunCommon/Crypto/` with an identical wire
format, cross-validated by fixture vectors committed to both repos. Divergence
between the two implementations is the most likely source of silent breakage, so
the fixtures are the real specification.

### Shared tables

| Table | Purpose |
|---|---|
| `crypto_orgs` | org id, ICAO, display name, status |
| `crypto_org_keys` | generation, enc pubkey, signing pubkey, root signature, valid_from/until, revoked |
| `crypto_org_members` | user_id → org, role, device key id, wrapped org material |
| `crypto_user_keys` | pilot identity/enc pubkeys, TOFU first-seen |

Per `db.md` convention: `user_id` as `String(64)`, indexed, **no** FK — key
rows must survive user deletion for historic verification. Migrations use
`batch_alter_table` (SQLite dev / MySQL prod).

## Key choices

- **HPKE envelope over a ratchet** — matches the actual message shape (one-shot,
  organisational reader, long retention). A ratchet solves a problem we do not
  have and breaks three we do.
- **Per-field-group DEKs, not per-submission** — lets a handling agent see
  contact details while only customs sees passport numbers, from one submission.
  This is what makes "seen by one party but not another" a first-class property
  instead of a special case.
- **Wrap to org, wrap org to devices** — the only shape where staff rotation
  and historic access coexist.
- **Offline root over transparency log** — strictly stronger, and cheaper at our
  onboarding scale. Revisit only if manual signing becomes the bottleneck.
- **No flyfun-held escrow** — accepting a real support burden to keep the
  subpoena-resistance property honest.
- **Client-side blind index** — buys the history feature without giving the
  server plaintext, at the cost of an admitted linkage-graph leak.

## Gotchas

- **Fernet is not this.** `flyfun_common.encryption` uses a server-held key.
  Never route submission payloads through it.
- **Non-extractable WebCrypto keys limit key theft, not plaintext theft.** A
  backdoored console can read decrypted data regardless. Do not let this detail
  become the basis for a stronger claim than the threat model supports.
- **`Depends()` footgun** (see CLAUDE.md): key-loading helpers will be tempting
  to use both as DI dependencies and directly. Split pure from DI wrapper from
  the start.
- **Canonicalisation drift** silently breaks signature verification across the
  Python/Swift boundary. Fixture vectors in CI on both sides, not unit tests
  written twice.
- **Clock skew** breaks `valid_from` checks on airport desktops. Allow a
  generous window and never hard-fail decryption on time alone.
- **Rotating `index_key` orphans history.** Treat it as near-permanent; rotate
  the encryption key independently.

## Open questions

- Console as web app (adoption) vs native/Electron (real integrity)? The threat
  model materially differs. Probably: web to prove the loop, native if a
  regulator asks the hard question.
- Do we ever need an airport to hand data to a *third* party (border police,
  handling agent) without re-encryption by the pilot? Re-wrapping by the airport
  is possible but changes the "only the addressed airport" claim.
- Multi-country legs: one bundle per airport, or per authority? Sion and a
  French field have different legal drivers — see the product doc.

## References

- [submission-server](../../flyfun-forms/designs/submission-server.md) — product design that consumes this
- [auth](./auth.md) — OAuth, JWT, SSO; magic-link path for airport staff
- [db](./db.md) — shared table conventions
- RFC 9180 (HPKE), RFC 8785 (JCS)
