// SPDX-License-Identifier: BSD-3-Clause

package wireguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The names a provider and a gateway share.
const (
	// ListType is the "typ" of a signed [List]: not "JWT", so that nothing
	// verifying tokens takes a list for one, nor the reverse.
	ListType = "wireguard-peers+jwt"
	// ListPath is where a provider serves the list, under its issuer.
	ListPath = "/wireguard/peers"
	// KeyPath is where a person's client registers and removes a key.
	KeyPath = "/wireguard/key"
	// ScopeKeys is the scope a person's token needs to register a key.
	ScopeKeys = "wireguard"
	// ScopePeers is the scope a gateway's own token needs to read the list.
	ScopePeers = "wireguard_peers"
)

// Peer is one key a person registered, as a gateway needs it.
type Peer struct {
	Key Key
	// Subject is the person's "sub" as the client that registered the key
	// sees it: the value a gateway also finds in that person's access
	// tokens, whether the client's subjects are public or pairwise.
	Subject string
	// Username is the name the provider calls them, for logs and routing
	// rules; Subject is what ties a key to a person.
	Username string
	// Device is the name the person gave the key, if any.
	Device string
	// Expires is the end of the key's lease. A gateway removes the peer then,
	// list or no list.
	Expires time.Time
}

// List is the keys a gateway may accept, at one moment.
type List struct {
	// Version increases every time a key is taken back. A gateway that has
	// seen a version refuses an older one, so an old list -- signed, and
	// listing a key since revoked -- cannot be replayed to it.
	Version uint64
	// IssuedAt is when the provider wrote it, and Expires when it stops
	// being an answer: a gateway that cannot fetch a newer one by then has
	// no list rather than a stale one.
	IssuedAt, Expires time.Time
	Peers             []Peer
}

// wirePeer is a Peer in the list's claims.
type wirePeer struct {
	Key      string `json:"public_key"`
	Subject  string `json:"sub"`
	Username string `json:"username,omitempty"`
	Device   string `json:"device,omitempty"`
	Expires  int64  `json:"exp"`
}

// Claims are the claims of the JWT a provider signs for one gateway, the
// audience. The provider signs them with [ListType] as the "typ".
func (l List) Claims(issuer, audience string) map[string]any {
	peers := make([]wirePeer, 0, len(l.Peers))
	for _, p := range l.Peers {
		peers = append(peers, wirePeer{Key: p.Key.String(), Subject: p.Subject, Username: p.Username, Device: p.Device, Expires: p.Expires.Unix()})
	}
	return map[string]any{
		"iss": issuer, "aud": audience,
		"iat": l.IssuedAt.Unix(), "exp": l.Expires.Unix(),
		"version": l.Version, "peers": peers,
	}
}

// listFromClaims reads the list's own claims, after the token around them
// has been verified.
func listFromClaims(version json.RawMessage, peers json.RawMessage, iat, exp time.Time) (*List, error) {
	l := &List{IssuedAt: iat, Expires: exp}
	if err := json.Unmarshal(version, &l.Version); err != nil {
		return nil, fmt.Errorf("wireguard: the list's version: %w", err)
	}
	var wire []wirePeer
	if err := json.Unmarshal(peers, &wire); err != nil {
		return nil, fmt.Errorf("wireguard: the list's peers: %w", err)
	}
	seen := make(map[Key]bool, len(wire))
	for _, w := range wire {
		k, err := ParseKey(w.Key)
		if err != nil {
			return nil, err
		}
		// One key, two people: whichever a gateway kept, the other's traffic
		// would arrive under the wrong name. A provider never writes this;
		// a list that says it is not one.
		if seen[k] {
			return nil, fmt.Errorf("wireguard: the key %s is listed twice", k)
		}
		seen[k] = true
		if w.Subject == "" {
			return nil, errors.New("wireguard: a peer with no subject belongs to nobody")
		}
		l.Peers = append(l.Peers, Peer{Key: k, Subject: w.Subject, Username: w.Username, Device: w.Device, Expires: time.Unix(w.Expires, 0)})
	}
	return l, nil
}
