package wireguard

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// provider is a go-authn provider as far as a gateway can see one: discovery,
// a key set, a token endpoint for the gateway's own client, and the list.
type provider struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	list   func(iss string) (map[string]any, map[string]any) // header, claims
	tokens int
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &provider{t: t, key: k}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	iss := p.srv.URL
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "jwks_uri": iss + "/jwks", "token_endpoint": iss + "/token"})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "gw" || secret != "s3cret" || r.FormValue("grant_type") != "client_credentials" || r.FormValue("scope") != ScopePeers {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client"})
			return
		}
		p.mu.Lock()
		p.tokens++
		p.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"access_token": "gateway-token", "token_type": "Bearer"})
	})
	mux.HandleFunc("GET "+ListPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gateway-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		h, c := p.list(iss)
		w.Write([]byte(p.sign(h, c)))
	})
	return p
}

func (p *provider) sign(header, claims map[string]any) string {
	p.t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			p.t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signed := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		p.t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func listHeader() map[string]any { return map[string]any{"alg": "RS256", "kid": "k1", "typ": ListType} }

func sampleList(version uint64, peers ...Peer) List {
	now := time.Now()
	return List{Version: version, IssuedAt: now, Expires: now.Add(5 * time.Minute), Peers: peers}
}

func source(t *testing.T, p *provider) *Source {
	t.Helper()
	s, err := NewSource(context.Background(), SourceConfig{Issuer: p.srv.URL, ClientID: "gw", ClientSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustKey(t *testing.T, s string) Key {
	t.Helper()
	k, err := ParseKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

const (
	keyA = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
	keyB = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
)

func TestAGatewayReadsItsList(t *testing.T) {
	p := newProvider(t)
	exp := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	want := sampleList(7,
		Peer{Key: mustKey(t, keyA), Subject: "sub-a", Username: "alice@univ.example", Device: "laptop", Expires: exp},
		Peer{Key: mustKey(t, keyB), Subject: "sub-b", Expires: exp})
	p.list = func(iss string) (map[string]any, map[string]any) { return listHeader(), want.Claims(iss, "gw") }

	got, err := source(t, p).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 7 || len(got.Peers) != 2 {
		t.Fatalf("got version %d with %d peers", got.Version, len(got.Peers))
	}
	a := got.Peers[0]
	if a.Key != mustKey(t, keyA) || a.Subject != "sub-a" || a.Username != "alice@univ.example" || a.Device != "laptop" || !a.Expires.Equal(exp) {
		t.Errorf("the first peer came back as %+v", a)
	}
	if got.Expires.Before(time.Now()) || got.IssuedAt.IsZero() {
		t.Errorf("the list's times: issued %v, expires %v", got.IssuedAt, got.Expires)
	}
}

// ⛔ What a gateway must not take for a list. Each is otherwise a list the
// provider could have signed.
func TestWhatIsNotAListIsRefused(t *testing.T) {
	good := func(iss string) map[string]any {
		return sampleList(1, Peer{Key: mustKey(t, keyA), Subject: "a", Expires: time.Now().Add(time.Hour)}).Claims(iss, "gw")
	}
	for _, tc := range []struct {
		name string
		list func(iss string) (map[string]any, map[string]any)
		want string
	}{
		{"an access token, typ at+jwt", func(iss string) (map[string]any, map[string]any) {
			h := listHeader()
			h["typ"] = "at+jwt"
			return h, good(iss)
		}, "type"},
		{"no typ", func(iss string) (map[string]any, map[string]any) {
			h := listHeader()
			delete(h, "typ")
			return h, good(iss)
		}, "type"},
		{"another gateway's list", func(iss string) (map[string]any, map[string]any) {
			c := good(iss)
			c["aud"] = "other-gw"
			return listHeader(), c
		}, "addressed"},
		{"expired", func(iss string) (map[string]any, map[string]any) {
			c := good(iss)
			c["exp"] = time.Now().Add(-time.Hour).Unix()
			return listHeader(), c
		}, "expired"},
		{"another issuer", func(iss string) (map[string]any, map[string]any) {
			c := good(iss)
			c["iss"] = "https://elsewhere.example"
			return listHeader(), c
		}, "from"},
		{"one key twice", func(iss string) (map[string]any, map[string]any) {
			exp := time.Now().Add(time.Hour)
			return listHeader(), sampleList(1, Peer{Key: mustKey(t, keyA), Subject: "a", Expires: exp}, Peer{Key: mustKey(t, keyA), Subject: "b", Expires: exp}).Claims(iss, "gw")
		}, "twice"},
		{"a peer of nobody", func(iss string) (map[string]any, map[string]any) {
			return listHeader(), sampleList(1, Peer{Key: mustKey(t, keyA), Expires: time.Now()}).Claims(iss, "gw")
		}, "nobody"},
		{"a key of low order", func(iss string) (map[string]any, map[string]any) {
			c := good(iss)
			c["peers"] = []any{map[string]any{"public_key": base64.StdEncoding.EncodeToString(make([]byte, 32)), "sub": "a", "exp": 1}}
			return listHeader(), c
		}, "low order"},
		{"no version", func(iss string) (map[string]any, map[string]any) {
			c := good(iss)
			delete(c, "version")
			return listHeader(), c
		}, "version"},
		{"a version that is not a number", func(iss string) (map[string]any, map[string]any) {
			c := good(iss)
			c["version"] = "7"
			return listHeader(), c
		}, "version"},
		{"no peers", func(iss string) (map[string]any, map[string]any) {
			c := good(iss)
			delete(c, "peers")
			return listHeader(), c
		}, "peers"},
		{"peers that are not a list", func(iss string) (map[string]any, map[string]any) {
			c := good(iss)
			c["peers"] = map[string]any{}
			return listHeader(), c
		}, "peers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newProvider(t)
			p.list = tc.list
			_, err := source(t, p).Fetch(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%v, want an error about %q", err, tc.want)
			}
		})
	}
}

// ⛔ An old list is signed too, and it may list a key taken back since.
// Within its lifetime it would be accepted on its signature alone; the
// version is what refuses it.
func TestAnOlderListIsNotReplayed(t *testing.T) {
	p := newProvider(t)
	version := uint64(5)
	p.list = func(iss string) (map[string]any, map[string]any) {
		return listHeader(), sampleList(version, Peer{Key: mustKey(t, keyA), Subject: "a", Expires: time.Now().Add(time.Hour)}).Claims(iss, "gw")
	}
	s := source(t, p)
	if _, err := s.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	version = 5 // the same version again is the same answer
	if _, err := s.Fetch(context.Background()); err != nil {
		t.Errorf("the same version twice: %v", err)
	}
	version = 4
	if _, err := s.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "older") {
		t.Errorf("an older list: %v", err)
	}
	version = 6
	if l, err := s.Fetch(context.Background()); err != nil || l.Version != 6 {
		t.Errorf("a newer list: %v", err)
	}
}

func TestTheGatewayMustBeAClientOfItsOwn(t *testing.T) {
	p := newProvider(t)
	p.list = func(iss string) (map[string]any, map[string]any) {
		return listHeader(), sampleList(1).Claims(iss, "gw")
	}
	if _, err := NewSource(context.Background(), SourceConfig{Issuer: p.srv.URL, ClientID: "gw"}); err == nil {
		t.Error("a gateway with no secret was set up")
	}
	s, err := NewSource(context.Background(), SourceConfig{Issuer: p.srv.URL, ClientID: "gw", ClientSecret: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("a wrong secret: %v", err)
	}
}

// A secret and a list cross only protected links; loopback has none to
// listen on.
func TestOnlyProtectedURLs(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://login.example.org/token": true,
		"http://127.0.0.1:8080/token":     true,
		"http://[::1]:8080/token":         true,
		"http://localhost/token":          true,
		"http://login.example.org/token":  false,
		"ftp://login.example.org/token":   false,
		"://":                             false,
	} {
		if err := protected(raw); (err == nil) != ok {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

// The ways a provider can fail a gateway, each a refusal that says where.
func TestAProviderThatFails(t *testing.T) {
	ctx := context.Background()
	// Nobody there at all.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	if _, err := NewSource(ctx, SourceConfig{Issuer: dead.URL, ClientID: "gw", ClientSecret: "s"}); err == nil {
		t.Error("a provider that is not there was set up")
	}

	// A token endpoint in the clear, on a host that is not loopback.
	p := newProvider(t)
	cleartext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]any{"issuer": "http://" + r.Host, "jwks_uri": "http://" + r.Host + "/jwks", "token_endpoint": "http://login.example.org/token"})
			return
		}
		p.srv.Config.Handler.ServeHTTP(w, r)
	}))
	defer cleartext.Close()
	if _, err := NewSource(ctx, SourceConfig{Issuer: cleartext.URL, ClientID: "gw", ClientSecret: "s"}); err == nil || !strings.Contains(err.Error(), "token endpoint") {
		t.Errorf("a token endpoint in the clear: %v", err)
	}

	// An answer that is not a 200.
	half := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer half.Close()
	if err := getJSON(ctx, http.DefaultClient, half.URL+"/elsewhere", new(any)); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("a non-200 answer: %v", err)
	}
	if err := getJSON(ctx, http.DefaultClient, "http://login.example.org/x", new(any)); err == nil {
		t.Error("a cleartext URL was fetched")
	}

	// The list endpoint refuses, or the token endpoint answers nonsense, or
	// the provider goes away after the gateway started.
	p.list = func(iss string) (map[string]any, map[string]any) {
		return listHeader(), sampleList(1).Claims(iss, "gw")
	}
	s := source(t, p)
	s.cfg.Issuer = p.srv.URL + "/nowhere" // the list's URL now 404s
	if _, err := s.Fetch(ctx); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("a list endpoint answering 404: %v", err)
	}
	s.cfg.Issuer = p.srv.URL
	s.tokenURL = p.srv.URL + "/jwks" // JSON, but GET-only: a 405 page, not JSON
	if _, err := s.Fetch(ctx); err == nil || !strings.Contains(err.Error(), "token") {
		t.Errorf("a token endpoint answering nonsense: %v", err)
	}
	s.tokenURL = "://"
	if _, err := s.Fetch(ctx); err == nil {
		t.Error("a token endpoint that is not a URL")
	}
	s.tokenURL = p.srv.URL + "/token"
	s.cfg.Issuer = "://"
	if _, err := s.Fetch(ctx); err == nil {
		t.Error("an issuer that is not a URL")
	}
	s.cfg.Issuer = p.srv.URL

	// The connection cut before the list, and in the middle of it.
	cut := func(mid bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != ListPath {
				p.srv.Config.Handler.ServeHTTP(w, r)
				return
			}
			if mid {
				w.Header().Set("Content-Length", "1000")
				w.Write([]byte("eyJ"))
			}
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
		}))
	}
	for _, mid := range []bool{false, true} {
		c := cut(mid)
		s.cfg.Issuer = c.URL
		if _, err := s.Fetch(ctx); err == nil || !strings.Contains(err.Error(), "the list") {
			t.Errorf("a connection cut (mid-body %v): %v", mid, err)
		}
		c.Close()
	}
	s.cfg.Issuer = p.srv.URL

	// Discovery that answers oidc.New and then fails the second ask.
	asked := 0
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			asked++
			if asked > 1 {
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"issuer": "http://" + r.Host, "jwks_uri": p.srv.URL + "/jwks"})
			return
		}
		http.NotFound(w, r)
	}))
	defer second.Close()
	if _, err := NewSource(ctx, SourceConfig{Issuer: second.URL, ClientID: "gw", ClientSecret: "s"}); err == nil {
		t.Error("a provider whose configuration could not be read twice was set up")
	}
	p.srv.Close()
	if _, err := s.Fetch(ctx); err == nil {
		t.Error("a provider that went away")
	}
}
