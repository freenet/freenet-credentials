# freenet-credentials

Credentials that Freenet apps can check: signed statements about a key, issued
by a service the app trusts, verifiable inside a contract.

The first credential is an **address attestation**: "on day D, the holder of
key K connected from an address whose tag, in context C, is T". The address
itself is never revealed. It is hashed with a secret key that only the issuer
holds, and the tag is scoped to one context (for example one River room), so
two rooms cannot compare their members' tags.

**Status: design discussion. There is no code yet.** This repository is a place
to work out the design before implementation starts. Please use
[Discussions](https://github.com/freenet/freenet-credentials/discussions) for
ideas, objections and questions.

## Why

Freenet apps that let anyone join need a way to limit abuse that does not cost
the user money and does not identify them. Today the
[River](https://github.com/freenet/river) Freenet Official room gets its new
members through an invite service on freenet.org that limits invites per IP
address. Once an invite is issued, the room knows nothing about where it came
from, so a moderator's ban cannot follow the person banned: they request a
new invite the next day.

An address attestation moves that limit into room state, where every peer can
check it. A River room could then:

- admit members who present an attestation instead of an invite,
- cap how many current members may share one address,
- make a ban on a member also ban their address tag for a while.

Other uses: rate limits and quotas in any contract, a free anti-spam gate for
[freenet-trust](https://github.com/freenet/freenet-trust) reports, and showing
in [Atlas](https://github.com/freenet/atlas) which rooms a user can join.

## What it cannot do

It does not prove one person. A household, an office or a mobile carrier's
shared address range can look like one address, and VPN, cloud and proxy
addresses are cheap. It raises the cost of creating many accounts, and makes
bans cost something; it is not an identity check.
[Ghost keys](https://freenet.org/ghostkey/), which cost a donation, remain the
stronger option, and a room could accept either.

## The design

[DESIGN.md](DESIGN.md) has the full draft:

1. how River invites work today, and where IP addresses already appear,
2. the attestation: issuer, tag construction, granularity (IPv4 /32 and /24,
   IPv6 /64 and /48), format, expiry and replay,
3. the River changes: admission by attestation, per-address caps, and bans
   that stick to the address tag,
4. the relationship to ghost keys and freenet-trust,
5. the `freenet-credentials` crate, the delegate that holds keys and
   attestations, and discovery in Atlas,
6. a suggested order of work,
7. open questions, ranked.

The open questions are where feedback is most useful.

## License

[LGPL-3.0](LICENSE), like the rest of the Freenet ecosystem.
