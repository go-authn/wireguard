// SPDX-License-Identifier: BSD-3-Clause

package wireguard

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
)

// Key is a WireGuard public key: an X25519 public value, 32 bytes.
type Key [32]byte

// ParseKey reads a public key as wg(8) prints it: standard base64, 44
// characters with its padding.
//
// It refuses:
//
//   - any other spelling of the same bytes. The decoding is strict, so a key
//     has exactly one text form, and a list or a store keyed on the text
//     cannot hold one key twice under two names;
//   - a key of low order, the all-zero key among them. Every exchange with
//     one gives the same shared secret whatever the other side's key (RFC
//     7748 6.1), so it authenticates nobody, and WireGuard itself refuses the
//     handshake. Registered, it would be a peer that cannot connect, holding
//     an address, and a name in the list for nothing.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("wireguard: the key is not base64: %w", err)
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("wireguard: a key is %d bytes, and this is %d", len(k), len(b))
	}
	copy(k[:], b)
	if k.String() != s {
		// Strict decoding refuses stray bits; this refuses everything else
		// that decodes to the same bytes, newlines included.
		return Key{}, errors.New("wireguard: the key is not in its canonical form")
	}
	if lowOrder(k) {
		return Key{}, errors.New("wireguard: the key is a point of low order, which authenticates nobody")
	}
	return k, nil
}

// String is the key as wg(8) prints it.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// probe is any private key: an exchange with a low-order point gives zero
// whatever the scalar, since X25519 clamps every scalar to a multiple of the
// cofactor.
var probe, _ = ecdh.X25519().NewPrivateKey([]byte("go-authn/wireguard: low order?..")) // 32 bytes: all it checks

// lowOrder is whether an exchange with k gives the all-zero secret, which
// crypto/ecdh refuses (RFC 7748 6.1).
func lowOrder(k Key) bool {
	// For X25519 NewPublicKey checks the length alone, which a Key cannot
	// get wrong.
	pub, _ := ecdh.X25519().NewPublicKey(k[:])
	_, err := probe.ECDH(pub)
	return err != nil
}
