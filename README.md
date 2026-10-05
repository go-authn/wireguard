# go-authn/wireguard

**WireGuard public keys for the people a go-authn provider knows.** It does
two things: it says what a public key is, and it carries the signed list of
keys people have registered, which a gateway turns into peers.

WireGuard authenticates a peer by its static public key and by nothing else.
The protocol has no certificates, no expiry and no revocation. The question
*may this key connect, and whose is it?* therefore has to be answered outside
it, and answered again whenever the answer changes.
[go-authn/bridge](https://github.com/go-authn/bridge) answers it:

```text
device            bridge                               gateway (claimward)
  │ wg genkey (stays here)
  │── token, scope "wireguard" ──▶ POST /wireguard/key {public_key, device}
  │                                  key → person, for a lease;
  │                                  DisablePerson / DisableIdP take it back
  │                                                       │
  │                    GET /wireguard/peers  ◀────────────┤ its own client,
  │                    signed, typ wireguard-peers+jwt ──▶│ scope "wireguard_peers"
  │                                                       │ Source.Fetch → peers
  │                    SSF events (person disabled) ─────▶│ fetch again now
```

⛔ **Only public keys pass through here.** A private key is generated on the
device and never leaves it, and nothing in this package has a place for one.

## A key

`ParseKey` reads a key the way wg(8) prints it: standard base64, 44
characters with padding. It refuses two things:

- **Any other spelling of the same bytes.** Strict decoding, and the text
  must print back exactly as it came. A key therefore has one text form, and
  a store keyed on the text cannot hold one key twice under two names.
- **A point of low order**, the all-zero key among them. Every exchange with
  such a point gives the same shared secret whatever the other side's key
  (RFC 7748 §6.1), so it authenticates nobody, and WireGuard refuses the
  handshake. Registered, it would be a peer that cannot connect, holding an
  address. `crypto/ecdh` decides this by computing an exchange, so the
  top-bit variants are refused too, which a byte comparison would miss.
  The test checks the seven points libsodium lists, each with and without
  the top bit.

## The list

A `List` is signed by the provider as a JWT whose `typ` is
`wireguard-peers+jwt` (`ListType`). Neither an access token nor an ID token can
pass for one, and a list cannot pass for a token. It is addressed to one
gateway client and carries:

| claim | |
|---|---|
| `version` | increases every time a key is taken back |
| `iat`, `exp` | written, and stops being an answer; a gateway that cannot fetch a newer one by then has no list, rather than a stale one |
| `peers` | `public_key`, `sub`, `username`, `device`, `exp` (the key's lease) |

`sub` is the person's subject **as the client that registered the key sees
it**, public or pairwise. It is therefore the same value a gateway finds in
that person's access tokens.

`Source` is the gateway's side. `NewSource` reads the provider's configuration
at startup. `Fetch` then:

1. gets a token for the gateway itself (`client_credentials`, scope
   `wireguard_peers`, credentials sent as RFC 6749 §2.3.1 says);
2. fetches the list;
3. verifies it with [go-authn/oidc](https://github.com/go-authn/oidc): the
   signature against the provider's key set, the issuer, the audience (this
   gateway), the expiry and the `typ`.

It refuses:

| | why |
|---|---|
| a list **older** than one already seen | an old list is signed too, and may list a key taken back since; within its lifetime its signature alone would pass |
| a key **listed twice** | whichever a gateway kept, the other person's traffic would arrive under the wrong name |
| a peer with **no subject** | it belongs to nobody |
| a key that is not one (see above) | |
| an issuer or token endpoint **in the clear** | the gateway's secret and the list would cross a link anybody can read; loopback is exempt |

## The judge

The keys `ParseKey` must accept are made by **wg(8) itself** (wireguard-tools),
installed and required in the CI lanes that run the tests
(`WIREGUARD_REQUIRE_JUDGE=1`), so a missing judge fails rather than skips.
Elsewhere, pyca/cryptography's X25519 (OpenSSL) stands in. Coverage is
**100%**, and the CI floor is 100.

## Licence

BSD-3-Clause.
