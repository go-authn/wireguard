// SPDX-License-Identifier: BSD-3-Clause

package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-authn/oidc"
)

// SourceConfig is how a gateway reaches its provider.
type SourceConfig struct {
	// Issuer is the provider, as its tokens name it.
	Issuer string
	// ClientID and ClientSecret are the gateway's own client at the
	// provider: a confidential client the provider lets read the list.
	ClientID, ClientSecret string
	// Client is the HTTP client, for a proxy, a private CA or a timeout.
	Client *http.Client
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// A Source fetches a provider's list for one gateway. It is safe for
// concurrent use; build one at startup and keep it, since it remembers the
// newest version it has seen.
type Source struct {
	cfg      SourceConfig
	verifier *oidc.Verifier
	tokenURL string

	mu     sync.Mutex
	newest uint64
}

// NewSource reads the provider's configuration, as a database is pinged at
// startup: a provider that is not answering is a gateway that cannot admit
// anybody, and it should say so before it starts.
func NewSource(ctx context.Context, cfg SourceConfig) (*Source, error) {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("wireguard: a gateway reads the list as a client of its own, with a secret")
	}
	v, err := oidc.New(ctx, oidc.Config{Issuer: cfg.Issuer, Audience: cfg.ClientID, Type: ListType, Client: cfg.Client, Now: cfg.Now})
	if err != nil {
		return nil, err
	}
	var meta struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := getJSON(ctx, cfg.Client, cfg.Issuer+"/.well-known/openid-configuration", &meta); err != nil {
		return nil, err
	}
	if err := protected(meta.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("wireguard: the token endpoint: %w", err)
	}
	return &Source{cfg: cfg, verifier: v, tokenURL: meta.TokenEndpoint}, nil
}

// errRolledBack is a list older than one this source already took.
var errRolledBack = errors.New("wireguard: the provider sent an older list than one already seen")

// Fetch asks for the list and verifies it: signed by the provider, of the
// list's own type, addressed to this gateway, unexpired, and no older than
// the newest this Source has taken.
func (s *Source) Fetch(ctx context.Context) (*List, error) {
	token, err := s.token(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Issuer+ListPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := s.cfg.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wireguard: fetching the list: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("wireguard: reading the list: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wireguard: the provider answered %s for the list", res.Status)
	}
	tok, err := s.verifier.Verify(ctx, string(body))
	if err != nil {
		return nil, fmt.Errorf("wireguard: the list: %w", err)
	}
	var version, peers json.RawMessage
	if err := tok.Claim("version", &version); err != nil {
		return nil, fmt.Errorf("wireguard: the list has no version: %w", err)
	}
	if err := tok.Claim("peers", &peers); err != nil {
		return nil, fmt.Errorf("wireguard: the list has no peers: %w", err)
	}
	iat, _ := tok.IssuedAt()
	exp, _ := tok.Expiry()
	l, err := listFromClaims(version, peers, iat, exp)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if l.Version < s.newest {
		return nil, fmt.Errorf("%w (version %d after %d)", errRolledBack, l.Version, s.newest)
	}
	s.newest = l.Version
	return l, nil
}

// token is an access token for the gateway itself (RFC 6749 4.4), its
// credentials sent as RFC 6749 2.3.1 says: form-encoded, then Basic.
func (s *Source) token(ctx context.Context) (string, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {ScopePeers}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(s.cfg.ClientID), url.QueryEscape(s.cfg.ClientSecret))
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	res, err := s.cfg.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("wireguard: asking for a token: %w", err)
	}
	defer res.Body.Close()
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("wireguard: the token response (%s): %w", res.Status, err)
	}
	if res.StatusCode != http.StatusOK || out.AccessToken == "" {
		return "", fmt.Errorf("wireguard: no token for the gateway (%s): %q", res.Status, out.Error)
	}
	return out.AccessToken, nil
}

func getJSON(ctx context.Context, c *http.Client, u string, v any) error {
	if err := protected(u); err != nil {
		return err
	}
	// protected parsed it, so this cannot fail.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	res, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("wireguard: %s: %w", u, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("wireguard: %s answered %s", u, res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(v)
}

// protected refuses a URL a gateway's secret or its list would cross in the
// clear. Loopback is exempt: there is no link to listen on.
func protected(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			return nil
		}
	}
	return fmt.Errorf("%q is not https", raw)
}
