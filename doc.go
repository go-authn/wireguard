// SPDX-License-Identifier: BSD-3-Clause

// Package wireguard is what a go-authn provider and a WireGuard gateway agree
// on about people's keys: what a public key is, and the signed list of the
// keys people have registered, which the gateway turns into peers.
//
// WireGuard authenticates a peer by its static public key and nothing else:
// there are no certificates, no expiry and no revocation in the protocol. So
// the question "may this key connect, and whose is it?" has to be answered
// outside it, and answered again whenever the answer changes. Here the
// provider (go-authn/bridge) answers it: a person registers the public key of
// each device with a token, for a lease, and the provider takes the keys back
// when the person or their institution is disabled. The gateway pulls the
// answer as a [List], signed by the provider, with a [Source].
//
// ⛔ Only PUBLIC keys pass through here. A private key is generated on the
// device and never leaves it; nothing in this package has a place for one.
package wireguard
