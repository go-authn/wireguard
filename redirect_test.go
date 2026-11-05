// SPDX-License-Identifier: BSD-3-Clause

package wireguard

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Security audit 2026-11-05 (untracked proof). Source.token POSTs the
// gateway's client secret (Basic) with cfg.Client, which follows redirects.
// On a 307/308 Go re-sends the body and -- because only the host NAME is
// compared -- the Authorization header to the same host on any scheme or
// port. go-authn/rp refuses to follow a token-endpoint redirect for exactly
// this (rp.go:289-303); wireguard does not.
func TestSecAuditGatewaySecretFollowsTokenRedirect(t *testing.T) {
	var mu sync.Mutex
	var stolen string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, s, ok := r.BasicAuth(); ok {
			mu.Lock()
			stolen = s
			mu.Unlock()
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client"})
	}))
	defer other.Close()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	iss := srv.URL
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "jwks_uri": iss + "/jwks", "token_endpoint": iss + "/token"})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "k1", "use": "sig", "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/token", http.StatusTemporaryRedirect)
	})
	s, err := NewSource(context.Background(), SourceConfig{Issuer: iss, ClientID: "gw", ClientSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Fetch(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if stolen != "" {
		t.Errorf("the gateway's client secret %q was sent to %s after a redirect", stolen, other.URL)
	}
}

// The list request carries the gateway's Bearer token: a redirect from the
// list path must not receive it.
func TestSecAuditListBearerFollowsRedirect(t *testing.T) {
	var mu sync.Mutex
	var stolen string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		stolen = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer other.Close()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	iss := srv.URL
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "jwks_uri": iss + "/jwks", "token_endpoint": iss + "/token"})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "k1", "use": "sig", "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "bearer-secret", "token_type": "Bearer"})
	})
	mux.HandleFunc("GET "+ListPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/list", http.StatusTemporaryRedirect)
	})
	s, err := NewSource(context.Background(), SourceConfig{Issuer: iss, ClientID: "gw", ClientSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(context.Background()); err == nil {
		t.Error("a redirected list was accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	if stolen != "" {
		t.Errorf("the gateway's bearer token was sent to %s after a redirect: %q", other.URL, stolen)
	}
}
