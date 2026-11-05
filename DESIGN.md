# Address attestation: design draft

Status: draft for discussion, no code yet. Code references are to the main branches of the named repositories as of 2026-11-05 (river `b78f81f8`, web `f822a49e`). `web:` paths are in [freenet/web](https://github.com/freenet/web).

## Summary

- **River's invite is not an attestation of anything outside the room.** An invite is a room member signing "this public key may join this room". The inviter generates the invitee's key pair and ships the private key inside the invite, so the invite is a bearer credential. It carries no time, no expiry and no IP.
- **IP addresses already matter in exactly one place: the freenet.org invite API (gkapi).** It limits invites to the Freenet Official room per IP (4 per 24 hours by default), adds a global ceiling, proof of work and a Tor-exit block. After it decides, it throws the IP away; the room never learns anything about it. So the limit binds only gkapi's own invites, and a moderator ban cannot follow the person who was banned.
- **Recommended design:** a small signed statement, issued by a freenet.org service (gkapi), saying "on day D, the holder of key K connected from an address whose keyed tag in context C is T". The tag is a hash of the address with a secret salt, used as an HMAC key that only the issuer holds. All the privacy rests on that key: with it, any IPv4 tag is reversible in about a second, so its custody matters more than the hash choice. Tags are scoped to a context (for River, one room), so two rooms cannot match their members' tags against each other.
- **Two granularities:** IPv4 /32 and /24; IPv6 /64 and /48. A full /128 tag is useless for IPv6, because one household controls 2^64 addresses.
- **River changes:** a room can admit members who present an attestation instead of an invite. Bans on such members also ban their tag, with an expiry. The contract enforces a cap on members per tag. That moves the per-IP limit out of gkapi's server into room state that every peer verifies, and gkapi no longer needs to hold a hot inviter key for the Official room.
- **Ghost Keys:** share the root of trust (the master key certifying an issuer key, which the `info.action` field was designed for) and the verifier library. Keep the claim formats and issuance separate, and do not attach IP attestations to ghost keys by default. Apps get one crate (`freenet-credentials`) that verifies attestations in contracts and, on the client, talks to a new attestation delegate and the issuer. That delegate stays separate from the ghost key vault so attestation changes never re-key the store of paid keys. Atlas shows which rooms admit by attestation (section 5).
- **What it cannot do:** it does not prove one person. A CGNAT range or a university shares one tag; VPN, cloud and residential-proxy addresses are cheap. It raises the cost of Sybil keys to "one fresh address per N keys per day". Treat it as a rate limit and ban-evasion cost, not identity.

## 1. How River invites work today

### What is signed, and by whom

`common/src/room_state/member.rs:1335-1376`:

```rust
pub struct AuthorizedMember { pub member: Member, pub signature: Signature }
pub struct Member {
    pub owner_member_id: MemberId,
    pub invited_by: MemberId,
    pub member_vk: VerifyingKey,
}
```

The inviter, who must already be a member or the owner, signs the CBOR of `Member` with their own room key (`AuthorizedMember::new`, `:1341`). The contract checks every member's chain back to the room owner, verifying an Ed25519 signature per link (`MembersV1::verify`, `:43-82`; `verify_invite_link`, `:490-530`). The owner's key is the contract parameter.

What it proves: "a chain of members starting at the owner authorized this key". Nothing about who holds the key, when, or from where.

### The invitation artifact

`cli/src/api.rs:2649` and `ui/src/components/members.rs:160` (kept byte-identical by hand):

```rust
pub struct Invitation {
    pub room: VerifyingKey,
    pub invitee_signing_key: SigningKey,   // the invitee's PRIVATE key
    pub invitee: AuthorizedMember,
    #[serde(default)] pub room_secrets: Vec<(u32, [u8; 32])>,
}
```

The inviter generates the invitee's key pair (`build_invitation`, `api.rs:3937-3961`) and the encoded invitation is a bearer credential: whoever has the string can join as that member. The inviter knows the invitee's private key for ever. That is a reasonable trade for River's link-sharing UX, but it matters for attestation: an attestation about K says nothing useful if the issuer, or anyone who saw the link, also holds K's private key.

No timestamps or expiry exist anywhere in the member record. Bans carry `banned_at: SystemTime`, set by the banner (`ban.rs:818-822`).

There is a standing TODO at `member.rs:1332`: "need to generalize to support multiple authorization mechanisms such as ghost keys". This design is one answer to it.

### Where IP addresses enter: gkapi

The freenet.org quickstart page's "get an invite" button calls `https://gkapi.freenet.org` (`web: hugo-site/themes/freenet/layouts/partials/api-url.html:2`). The server (`web: rust/api/src/`) holds an inviter signing key for the Freenet Official room and mints invites with a re-implementation of River's types (`invite.rs`). Before minting it applies:

- per-IP limit: 4 per 24 h by default (configurable at runtime), keyed on the TCP peer address, or the rightmost `X-Forwarded-For` entry when the peer is the local Caddy (`rate_limit.rs:32`, `routes.rs:509-580`).
- global ceiling: 200 per hour (`rate_limit.rs:38`).
- proof of work: HMAC-authenticated, single-use, 5-minute challenges, difficulty 16 bits rising with load (`invite_pow.rs`).
- Tor exits: blocked or metered as one bucket (`tor.rs`). Its comments record a burst of 246 invites from 202 IPs, 200 of them through 159 Tor exits. That is direct evidence of how cheaply IP rotation defeats a per-IP limit.

The consequence that matters here: once the invite exists, the room sees only "gkapi's inviter key invited K". When River Marshal bans a spammer, the spammer requests another invite from the same IP the next day and gets one. The ban cannot follow the IP, because the room never had it.

### Where IP addresses enter: freenet-core

In freenet-core (paths under `crates/core/src/`):

- A joining peer learns its public address from the gateway's `ConnectMsg::ObservedAddress` (`operations/connect.rs:220-223`). Unsigned; protected only by the session encryption.
- Ring location is derived from the observed IP, masked to /24 for IPv4 and /48 for IPv6 "for sybil mitigation" (`ring/location.rs:35-51`), with IPv4-mapped IPv6 normalized first (`:20-31`). This is precedent for the prefix sizes proposed below.
- Over UDP, the initiating peer does not prove possession of its static key; the gateway's binding of key to address is "a claim" (`transport/metrics.rs:108-147`). The new QUIC path (#5940) does give mutual proof of possession, but only for a key the server already expects. So a gateway would need an explicit challenge to issue a sound attestation.
- The transport key can sign: `TransportKeypair::auth_token_signer()` produces XEdDSA signatures verifiable as Ed25519 (`transport/crypto.rs:102-113`).
- No per-IP or per-subnet connection caps, no dynamic IP bans. `blocked_addresses` is a static exact IP:port list.
- Contracts and delegates can learn nothing about IPs (stdlib host imports have no network information). Contracts also cannot read a clock, which constrains expiry checks (section 2.6).
- Gateway public keys come from `https://freenet.org/keys/gateways.toml`, trusted only through TLS. They are not certified by any Freenet key.

## 2. The attestation

### 2.1 The statement

"On day D, the holder of the private key for K completed a challenge over a connection from an address whose tag, in context C, at granularity G, is T. Signed, issuer I."

Two properties the statement must have:

1. **K is generated by the subject, never by the issuer.** Otherwise "the holder of K" includes the issuer. For River this means the joining client (UI, riverctl or the quickstart page's JS) generates the member key, and the issuer only ever sees the public half.
2. **The subject proves possession of K during the same connection** by signing the issuer's nonce. Over HTTPS, TCP gives return routability for the source address, so completing the request proves the client could receive traffic at that address at that moment.

### 2.2 Who issues it

| Candidate | Can see the IP | Can verify K | Trust for verifiers | Verdict |
|---|---|---|---|---|
| Any peer that saw the connection | yes | with a challenge | none; a Sybil runs its own peer and attests anything | reject |
| Gateways | yes (UDP source) | needs an XEdDSA challenge, or QUIC | gateway keys would need master certification; today they are TLS-trusted only | later, if ever |
| gkapi (freenet.org) | yes (TCP via Caddy) | signed nonce | issuer key certified by the Ghost Keys master key | **v1** |

Recommendation: one issuing service, gkapi, for the first version. Reasons:

- It already sees client IPs, already has the challenge, proof-of-work and Tor-exit machinery, and already runs the Official room's anti-spam.
- **Tags from different issuers are not comparable** unless the issuers share the secret key. A room accepting several issuers lets a banned person switch issuer, and sharing the secret across many gateways enlarges the set of machines whose compromise exposes every tag. One issuer avoids both problems. The service can still run on more than one machine with the same key if availability requires it.

Trust anchor: the Ghost Keys master key (`web: rust/gklib/src/lib.rs:11`; the private key is kept offline) signs an issuer certificate in the existing `NotaryCertificateV1` shape, with `info = {"action":"ip-attestation", "issuer-key-created": ..., "context-scheme": 1}`. `gkverify/src/info.rs` already tells verifiers to check `action` "so a future kind of notary is not taken for one". The issuer key itself is Ed25519 (no blind signing needed, see 2.7), rotated on a schedule like the notary keys, with each new key certified offline.

### 2.3 The tag: who holds the "salt" and what it buys

The address is hashed with a secret salt. A secret salt is in effect an HMAC key, and the design calls it one below. The point of this section is how much rests on that key staying secret, because the input space is small enough that anyone holding the key can recover addresses from tags:

| Input space | Count | HMAC-SHA256 brute force if the key is known |
|---|---|---|
| IPv4 /32 | 2^32 ≈ 4.3 billion | about 1 s on one current GPU; under a minute on a multi-core CPU |
| IPv4 /24 | 2^24 ≈ 16.8 million | milliseconds |
| IPv6 /64, attacker knows the ISP's /32 | 2^32 | as IPv4 /32 |
| IPv6 /48, attacker knows the ISP's /32 | 2^16 | instant |
| IPv6, ISP unknown | the routed space is published in BGP tables (~10^5 prefixes) | hours to days on GPUs, and a candidate IP from any log confirms with one hash |

So:

- **Secret key held only by the issuer (recommended):** the tag is a keyed pseudonym, `T = HMAC(k, ...)`. Verifiers can test only equality between tags; nobody but the issuer can invert or confirm a guess. Call it a "keyed tag" in code and docs, so nobody later mistakes it for a hash that is safe to publish with its salt.
- **If the key leaks**, every tag ever issued under it is recoverable in the times above, and the same holds if the issuer's host is compromised. Today the same host already stores raw IPs for its rate limit, so the key does not add a new class of exposure. A slow hash (Argon2 at ~100 ms) would turn a leaked-key /32 search into roughly 14 CPU-years, parallelizable; /24 would still be ~20 CPU-days. That is real but modest protection, and it costs the issuer 100 ms per issuance. Optional; probably not worth it for v1.
- **Key shared between several issuers vs one key per issuer:** a shared key makes tags comparable across issuers, so a ban holds whichever issuer the person goes to. But every issuing machine then holds the one key whose leak exposes all tags. Per-issuer keys contain a leak to one issuer but let a banned person switch issuer. With a single issuer (section 2.2) the question does not arise; it returns if gateways ever issue.

Key derivation:

```
k_ctx  = HMAC-SHA256(master_tag_key, "freenet-ip-tag-v1" || generation || context)
T_full = HMAC-SHA256(k_ctx, family || "full"   || canonical_full_prefix)[..16]
T_pfx  = HMAC-SHA256(k_ctx, family || "prefix" || canonical_short_prefix)[..16]
```

- `context` (32 bytes) scopes the tag. For River it is a hash of the room owner key, so room A cannot tell that a member of room B shares an address with one of its members. An all-zero context means "global" and should require a reason.
- `generation` rotates the key. Rotation stops long-term tracking but also breaks the link between tags before and after, so a ban on a tag lapses at rotation. Because IPs get reassigned anyway, bans on tags should be short-lived (section 3.4), and a yearly generation is a reasonable compromise. See open question 3.
- Canonicalize first: unmap IPv4-mapped IPv6 the way `ring/location.rs:20-31` does, so one host does not get two tags.
- 16-byte tags: collisions are negligible at any plausible scale and they keep room state small.

### 2.4 Granularity

| Family | "full" tag | "prefix" tag | Why |
|---|---|---|---|
| IPv4 | /32 | /24 | /24 as originally proposed; matches the ring-location mask. |
| IPv6 | /64 | /48 | /64 is the standard single-subnet allocation; one household or one VM almost always controls a whole /64 (and privacy addresses rotate inside it daily), so a /128 tag would give one person unlimited tags. /48 is the common site allocation and matches the ring-location mask. Residential ISPs often hand out a /56; /48 covers it. |

The /24 and /48 prefixes catch more innocent neighbours than the full tags: a CGNAT /24 can hold thousands of unrelated mobile users. So the prefix tag should be used for escalation (a second ban on the same prefix) and for loose caps, not for the default ban.

Issue each granularity as a separately signed statement, so the subject can show a verifier only the one it needs. A room that only wants the /24 should not receive the /32.

### 2.5 Format

```rust
pub struct IpAttestationV1 {
    pub issuer_cert: IssuerCertificateV1, // master-signed, action = "ip-attestation"
    pub body: IpAttestationBody,
    pub signature: ed25519::Signature,     // issuer key over "freenet-ip-attestation-v1" || CBOR(body)
}
pub struct IpAttestationBody {
    pub subject: VerifyingKey,     // K, Ed25519 (a transport key can use XEdDSA)
    pub context: [u8; 32],
    pub generation: u16,           // tag-key generation
    pub family: IpFamily,          // V4 | V6
    pub granularity: Granularity,  // Full | Prefix
    pub tag: [u8; 16],
    pub issued_day: u32,           // days since 1970-01-01, UTC
    pub valid_days: u16,           // suggested freshness for admission decisions
}
```

Size: about 230 bytes including the issuer certificate; the certificate can be deduplicated in state.

Time is a day, not a second. "At time T" to the second would make each attestation unique and linkable to the issuer's logs; a day keeps the anonymity set at "everyone attested from that tag that day", and nothing in the uses below needs finer time.

### 2.6 Expiry and replay

- **Replay by another key:** impossible; the attestation names K, and every use requires a signature by K (for River, the member record is self-signed by K).
- **Transfer:** a holder can hand over K together with the attestation. That is the same as lending one's address, so it gives an attacker nothing they could not get by controlling the address.
- **Staleness:** "controlled A on day D" stays true for ever; the question is how old a verifier accepts. Contracts cannot read the clock, so a River contract cannot check `issued_day + valid_days >= today`. Two workable substitutes:
  - Clients (UI, delegate, riverctl) check freshness against their clock before submitting, which catches honest mistakes.
  - The contract keeps a "room clock" = the largest `issued_day` it has accepted from the issuer, and rejects attestations older than `room_clock - max_age_days`. It is driven by issuer-signed times, so a member cannot advance it. In a quiet room it lags, which only makes it more lenient.
- **Issuance replay:** reuse gkapi's existing single-use HMAC challenge, and bind the challenge to the requesting address's tag so a challenge fetched from one address cannot be redeemed from another.

### 2.7 Issuance protocol (HTTPS on gkapi)

1. `GET /attest-challenge` returns `{nonce, issued_at, difficulty, mac}`, where the mac covers the requester's full tag. Optional proof of work, as for invites.
2. The client generates K locally and sends `POST /attest {K, context, granularities, challenge, pow_nonce, sig_K("freenet-ip-attest-request-v1" || challenge || context || K)}`.
3. The server checks the mac, single use, the tag match, the proof of work, Tor and its rate limits. **The rate limiter keys on the full tag (IPv6 /64), not the raw address, and stores tags rather than raw IPs.** It does not log the IP next to K.
4. It returns one `IpAttestationV1` per requested granularity.

The issuer necessarily sees (IP, K, context) at issuance. If that matters (open question 5), a partially blind signature (public part: tag, day, context; blinded part: K) would let the issuer sign without learning K. RFC 9474, which Ghost Keys uses, does not cover partially blind RSA; there is an IETF draft for it. Probably not worth the complexity in v1.

### 2.8 What it enables, and what it cannot prove

Uses it makes possible:

- **River admission without an invite, with a per-address cap and bans that follow the address** (section 3). This is the main use.
- **Moving the Official room's anti-spam off gkapi:** the limit becomes room state that any peer verifies, so admission no longer depends on one server holding a hot inviter key.
- **freenet-trust claims:** freenet-trust (design only, no code) proposes a general "issuer signs a claim about a subject" scheme and rate-limits reports by ghost key or proof of work. An IP attestation is a third, free, gate for it.
- **Per-address quotas in any contract:** free tiers, faucets, polls where "one vote per household per day" is good enough, comment spam limits.
- **Weak:** network-level Sybil defence. Peers already see their neighbours' addresses directly and ring location is already IP-derived, so an attestation adds little there.

What it cannot prove:

- **One person.** NAT puts a household, an office or a university behind one address; CGNAT puts thousands of mobile users behind a /24. Caps and bans will hit innocent neighbours, more so at prefix granularity.
- **That the attacker is resource-limited.** Cloud IPv4 costs well under a cent per address-hour, residential proxy networks sell rotating addresses, and IPv6 /64s are nearly free. The Tor comment in gkapi shows 202 IPs in one burst. The attestation raises the cost to "one address per N keys per day", which stops casual abuse and makes bans cost something; it does not stop a funded attacker. Ghost keys (paid) remain the strong option.
- **Continued control.** The subject may have a new address the next hour.
- **Location**, beyond what the tag hides anyway.
- **Anything about the subject if the issuer is dishonest.** The issuer can mint attestations for any tag. The design trusts freenet.org, as Ghost Keys already does.

Privacy cost to state plainly: within one context, every verifier (every member of a room) sees which members share a tag. Two people in one household joining one room are visibly linked. Enforcement needs that; the UI should say so at join time.

## 3. River: admission by attestation, and bans that stick to the tag

Every change below alters room contract WASM, so it re-keys the room contract and must go through River's contract migration procedure.

### 3.1 Room configuration

Add an optional field to `Configuration` (`configuration.rs:229`), byte-neutral the way `max_direct_messages` was added (`Option` plus `skip_serializing_if`, so old owner signatures still verify):

```rust
pub attested_admission: Option<AttestedAdmissionPolicy>,

pub struct AttestedAdmissionPolicy {
    pub issuer_root: VerifyingKey,          // the master key; issuer certs must chain to it
    pub required: Granularity,              // which tag a joiner must present (default Full)
    pub max_members_per_full_tag: u16,      // e.g. 2
    pub max_members_per_prefix_tag: u16,    // e.g. 20, or 0 = off
    pub max_attestation_age_days: u16,      // e.g. 2
    pub tag_ban_days: u16,                  // e.g. 30
    pub attested_members_may_invite: bool,
}
```

The context is derived from the room owner key, so it is not configurable and cannot be set to collide with another room.

### 3.2 Admission

Today a member record must be signed by an existing member and the chain must reach the owner. Add a second root type: a **self-signed member with an attestation**.

- `AuthorizedMember` gains `#[serde(default, skip_serializing_if = "Option::is_none")] admission: Option<IpAttestationV1>`, outside the signed `Member`, so existing records serialize unchanged.
- For an attested member, `invited_by == member.id()` and the signature is by the member's own key. Today `verify` rejects exactly this ("Self-invitation detected", `member.rs:73`); the rule becomes "self-invitation is allowed only with a valid attestation, and only when the room's policy is set".
- Contract checks for such a record: issuer certificate chains to `issuer_root` with `action == "ip-attestation"`; the attestation signature verifies; `subject == member_vk`; `context` matches this room; `granularity == required`; `issued_day >= room_clock - max_attestation_age_days`; the tag is not banned (3.4); the count of current members with this tag stays within the cap. Two Ed25519 verifications per admitted member, which fits the existing per-delta work bound reasoning (`member.rs:124`).
- In `verify_invite_chain`, an attested member is a chain root, like the owner. If `attested_members_may_invite` is false, a member whose chain root is an attested member (other than the owner) is rejected.
- The member cap is enforced at admission and on every apply, so a merge of two concurrent deltas cannot exceed it. Deterministic tie-break when it would: keep the records with the smaller `issued_day`, then the smaller member id, so every peer converges to the same set.

Join flow: the River UI (or riverctl, or the quickstart page) generates the member key locally, calls gkapi `/attest` with context = the room's context, and submits the self-signed member record. No invite link, and no private key ever leaves the client. For the Official room this replaces gkapi's invite minting entirely, and gkapi stops holding a room inviter key.

### 3.3 Why the cap is needed as well as the ban

The issuer limits attestations per tag per day (the current 4/day). Without a room cap, one address could still accumulate members over days. With `max_members_per_full_tag = 2`, a single address can hold at most two live members in the room, whatever the issuer's rate.

### 3.4 Bans that stick to the tag

Current bans (`ban.rs:736-822`): `UserBan { owner_member_id, banned_at, banned_user: MemberId }`, signed by the banner (owner or a deputy within their scope). The room already retains the `AuthorizedMember` record of a banned absent member in `ban_evidence` (`BanEvidenceV1`, `common/src/room_state.rs:243-250`, river#702), which is what makes a derived tag ban cheap:

- **Default: banning an attested member also bans their admission tag, derived by the contract.** The ban record is unchanged; the contract reads the tag from the retained banned member's attestation. Nothing new to sign, and River Marshal's existing ban path gets IP stickiness for free.
- **Escalation: an explicit prefix ban.** `UserBan` gains a byte-neutral optional `ban_prefix: bool`. When set, the contract also bans the banned member's prefix tag. This needs the banned member to have been admitted with a prefix attestation too, so the policy should either require both granularities at admission or accept that prefix bans only work when present. See open question 4.
- **Effect on admission:** an attestation whose tag matches a live tag ban is rejected.
- **Effect on current members:** when a tag ban lands, the contract also removes other attested members with the same tag. This is what catches sockpuppets admitted earlier from the same address. It is also the harshest effect on innocent housemates, so it should probably apply to full-tag bans only, not prefix bans. See open question 4.
- **Expiry:** IP addresses are reassigned, so a tag ban must expire, unlike a member ban. A tag ban is live while `room_clock < ban_day + tag_ban_days`, where `ban_day` is the room clock when the ban was applied. Using the issuer-signed room clock keeps it deterministic across peers. The member ban itself stays permanent.
- **Generation rotation** ends all tag bans issued under the previous generation, since tags are not linkable across generations. With a yearly generation and 30-day tag bans this loses at most one ban window per year.
- **Members admitted by invite** have no tag. A tag ban does not affect them, and banning one bans no tag. That is intended: an inviter vouched for them, and the existing invite-subtree ban cascade covers that path.
- **`max_user_bans`** bounds stored bans as today; derived tag bans add no records.

### 3.5 Other River changes

- UI: a "join" button on rooms whose policy allows attested admission; a privacy notice at join; in the member list and River Marshal's audit, a marker for "same network as a banned member" (a tag match with a ban that has expired) as information for moderators, not an automatic action.
- `riverctl`: `room join <owner_key>` performing the attest-and-self-admit flow.
- River Marshal: no change needed for the default; optionally a policy to escalate repeat offenders to `ban_prefix`.
- The chat delegate stores the member key as today. The attestation lives in room state, so the delegate needs no change unless the client wants to cache a fresh attestation for retries.
- gkapi: new `/attest-challenge` and `/attest` routes; switch the rate limiter to tags; retire `/create-invite` for the Official room once attested admission ships.

## 4. Relationship to Ghost Keys, and whether to combine

### What exists

Ghost Keys (`web: rust/gklib`, `rust/api`; `ghostkeys` repo for the delegate and vault):

- Chain: master Ed25519 key → per-tier, per-month RSA notary key → user's Ed25519 ghost key, signed blindly (RFC 9474). Proves "this key was bought with a donation of tier X in month M"; the server cannot link the key to the donation.
- Certificates never expire; time is coarse by design (monthly notary keys) to keep anonymity sets large.
- The vault is the ghostkey delegate: it stores certificate + private key per fingerprint in the delegate secret store (`gk:cert:{fp}`, `gk:sk:{fp}`, `gk:perms:{fp}`…), grants per-app scopes, and signs `ScopedPayload { requestor, payload }`, binding every signature to the runtime-attested calling app. It hard-codes `GhostkeyCertificateV1` and the master key throughout (import, default-key selection by donation tier, `HasIdentity` counts). Harvest uses it; River does not.

### Comparison

| | Ghost key | IP attestation |
|---|---|---|
| Proves | paid for, once | controlled an address, on a day |
| Purpose of the format | unlinkability: issuer cannot link key to payment | linkage: same-address detection within a context |
| Cost to the subject | money | an address |
| Lifetime | permanent | days |
| Issuance | blind RSA | ordinary signature; issuer sees IP and K |
| Subject key | one long-lived identity across apps | one key per context (room member key) |
| Strength vs funded attacker | strong | weak |

### Options

1. **Fully merged credential** (one certificate with optional donation and IP claims): rejected. Attaching an IP tag to a ghost key gives the issuer the ghost key ↔ IP mapping and gives verifiers a stable cross-context identifier next to an address tag. That defeats the property ghost keys are sold on. The lifetimes and issuance methods also differ.
2. **Shared root and verifier, separate claims** (recommended now): the master key certifies an `ip-attestation` issuer key in the existing `NotaryCertificateV1` envelope; one verification library (a generalized `gkverify`) understands both certificate actions; gkapi hosts both issuance endpoints. No new root of trust, no new offline key ceremony beyond certifying the issuer key, and the `action` field already exists for this.
3. **Generalized vault** (a typed credential store holding ghost keys, IP attestations and future claims, with the same permission and `ScopedPayload` model): sound in principle, and the storage layout, grants, prompts and migration machinery would carry over. What would change: a type tag in stored keys, a per-type import path and trust root, generalized `GhostKeyInfo`/`HasIdentity`/default selection, and a "present credentials" response; plus a delegate re-key through `legacy_delegates.toml`. Section 5 takes a different route: the client side does get a delegate, but a separate one from the vault, with one crate that talks to both. The reason is the re-key risk to paid keys, explained in 5.4.

The one combined use worth allowing: a room policy may accept *either* an IP attestation or a ghost key certificate for admission. That composes the two at the room level (a paying user skips the address cap) without merging the formats. It is also the natural answer to the `member.rs:1332` TODO.

Relationship to [freenet-trust](https://github.com/freenet/freenet-trust): freenet-trust proposes a general format for signed claims (an issuer says something about a subject, and each app chooses which issuers it honours), with moderation as its first use. An address attestation is that shape of statement, so the overlap is in the format, not the purpose. This project uses the same vocabulary (issuer, subject, claim, context) so address attestations can become a claim type in freenet-trust's format once it exists. Whether to merge the two earlier is open question 10.

## 5. Client crate, attestation delegate, and Atlas

How apps use attestations: a crate they include to talk to the delegate holding attested keys and certificates, and a way for users to see what their attestation lets them join.

### 5.1 One crate, two layers

A crate, `freenet-credentials` (following the `freenet-migrate` precedent of one shared crate instead of per-app copies), with two features:

- **`verify`**: types, issuer-certificate chain check to the master key, attestation signature check, and the tag-ban and cap helpers from section 3. No I/O, builds for WASM contracts. The River room contract uses this, so every app checks attestations the same way. Today gkapi re-implements River's types by hand (`web: rust/api/src/invite.rs` header says so); this layer prevents a second copy of that.
- **`client`**: what a UI or CLI calls. Typed requests to the attestation delegate, the HTTPS exchange with the issuer, and delegate-key resolution. Transport abstracted so the same code runs in a browser UI (fetch) and in riverctl (reqwest), the way `freenet-stdlib`'s `WebApi` is.

Sketch of the client surface:

```rust
let att = Credentials::connect(&web_api).await?;           // resolves the delegate via its pointer record
let grant = att.request_access().await?;                    // one user consent prompt per app
let a = att.attest(context, &[Granularity::Full]).await?;   // key + attestation for this context
let tags = att.lookup_tags(&contexts).await?;               // for the Atlas personal check (5.5)
let held = att.list().await?;                               // what this app may see
```

### 5.2 Who does what

Delegates cannot make network calls (stdlib host imports are only contract state, secrets, context, randomness, time and logging). That fits, because the issuer must see the user's own address, so the call has to come from the user's browser or CLI anyway.

`attest(context)` therefore runs:

1. Crate asks the delegate for a key for `context`. The delegate generates K (or reuses the one it holds for that context) and checks this app's grant.
2. Crate fetches the issuer challenge over HTTPS.
3. Delegate signs the challenge with K. The app never needs to see K's private half for this step.
4. Crate posts to the issuer, receives the attestation, and hands it to the delegate.
5. Delegate verifies it (using the `verify` layer) and stores it with K, keyed by context.

The delegate is also where the consent prompt lives ("River wants to attest your address for room X"). That prompt matters, because each attestation tells freenet.org which address is joining which room (open question 5).

### 5.3 Who holds the subject key

The simplest arrangement has the delegate holding the attested keys. That works for apps that sign rarely (an Atlas review, a freenet-trust claim, a Harvest listing): they sign through the delegate, as Harvest does with ghost keys today.

River is different. The member key signs every message, and River's chat delegate already holds room keys and signs with them. Routing every message through a second delegate adds a delegate-to-delegate round trip per message. Two options:

- **Export at join** (recommended for River): after attestation, the delegate exports K to River's chat delegate under an explicit `Export` grant, the same scope the ghost key vault already has. The attestation delegate keeps K and the attestation for re-attestation and lookups. River signs messages as it does now.
- **Sign through the delegate every time**: cleaner custody, slower messages, and a larger change to River's chat delegate.

### 5.4 Separate delegate from the ghost key vault

One crate can talk to both the attestation delegate and the vault, so apps get one dependency either way. The delegates themselves should stay separate:

- The vault holds keys users paid for. ghostkeys' own `pointer-records.toml` says getting its migration wrong is "unusually expensive" for exactly that reason, and the vault re-keyed twice in one day once (ghostkeys#21). Every change to delegate WASM re-keys it.
- An attestation feature will change often early on (policy fields, tag formats, issuer rotation). Putting it in the vault would re-key the paid-key store each time.
- Merging later is possible if both stabilize; splitting a merged store later is harder.

Both delegates need the existing addressing machinery: a pointer record so the crate resolves the current delegate key instead of pinning one, and `legacy_delegates.toml` plus a migration sweep so stored keys and attestations survive re-keys

### 5.5 Discovery in Atlas

Atlas already indexes River rooms (`crawler/src/main.rs:11`, `river-room <owner-vk>`), and its crawler reads room state, which is where the admission policy lives (3.1). So Atlas can show each room's requirement without a new registry: "anyone with an address attestation", "ghost key", or "invite only", with a "rooms I can join" filter. A separate listing page would be a second directory needing its own curation and anti-spam.

- **Generic view (first):** show the requirement only. A user who is banned or over the cap in a room finds out at join time. For most users the answer is the same.
- **Personal view (later, if users get confused by refused joins):** tags are per room, so whether *this* user is banned in room X depends on their tag for X, which only the issuer can compute. The client calls `lookup_tags` for every attestation-gated room in the index, not just the ones the user is interested in, so the issuer learns nothing about which rooms the user is considering. The client then compares the tags with each room's bans and member counts from room state. Lookup returns unsigned tags and does not count against the attestation rate limit.
- Storing the requirement: Atlas `IndexEntry` has a free-form `ext` map (`common/src/types.rs:343`), which likely avoids re-keying the index contract. A typed field is cleaner but goes through Atlas's re-key steps.
- Any other contract that admits by attestation can publish its policy in the same `ext` key, so the filter covers more than River.

## 6. Recommended path

1. Decide the open questions below.
2. gkapi: issuer key certified by the master key; `/attest-challenge` and `/attest`; switch the invite limiter to tags (useful on its own).
3. `freenet-credentials` crate (`verify` first, since the River contract needs it) and the attestation delegate with its pointer record.
4. River: configuration field, attested admission, derived tag bans with expiry, per-tag caps, join flow through the crate; with the contract migration rehearsal.
5. Official room: enable the policy, ship the UI join flow, retire gkapi's inviter key.
6. Atlas: show the room's requirement and a "rooms I can join" filter.
7. Later, only on demand: Atlas personal view; ghost-key-or-attestation admission; merging delegates; gateway issuers.

## 7. Open questions, ranked by how much depends on them

1. **Is "rate limit plus ban-evasion cost" the goal?** If the goal is one-person-one-account, IP attestation will disappoint and paid ghost keys (or both, either-or) are the answer. Everything else depends on this.
2. **Is freenet.org (gkapi) acceptable as the single issuer**, with the trust that implies: it sees (IP, K, room) at issuance and can mint any tag? The alternative, gateway issuers, needs gateway key certification and loses cross-issuer comparability.
3. **Tag-key rotation period.** The draft suggests yearly. Shorter improves privacy and shortens how long any tag ban can last; longer does the reverse.
4. **Ban defaults:** full-tag ban automatic on every ban of an attested member? Remove existing same-tag members on ban (catches sockpuppets, also removes housemates)? Prefix bans as an explicit escalation only?
5. **Should the issuer learn K?** Plain signatures (simple; issuer knows IP ↔ room member key, as gkapi already learns today when it issues an invite) versus partially blind signatures (issuer learns only the tag).
6. **Should attested members be allowed to invite others?** If yes, a banned person's friends' invites still work; if no, attested members are leaves.
7. **Default caps for the Official room:** members per full tag (2?), per prefix tag (20? off?), tag ban duration (30 days?), attestation freshness (2 days?).
8. **Separate attestation delegate, or extend the ghost key vault?** Recommended: separate delegate, one crate (5.4).
9. **River key custody:** export K to River's chat delegate at join (recommended), or sign every message through the attestation delegate (5.3)?
10. **Merge into freenet-trust now, or later?** This repo uses freenet-trust's vocabulary so address attestations can become one of its claim types. Building the code inside freenet-trust from the start would give that project a concrete second consumer, at the cost of tying this work to its design discussion.
