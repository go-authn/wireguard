package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// judgeKeys are public keys made by an implementation that is not this one:
// wg(8) itself when it is installed, otherwise pyca/cryptography's X25519
// (OpenSSL). Every one must parse, and print back as it came.
func judgeKeys(t *testing.T, n int) []string {
	t.Helper()
	if wg, err := exec.LookPath("wg"); err == nil {
		var out []string
		for range n {
			priv, err := exec.Command(wg, "genkey").Output()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(wg, "pubkey")
			cmd.Stdin = strings.NewReader(string(priv))
			pub, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, strings.TrimSpace(string(pub)))
		}
		return out
	}
	if os.Getenv("WIREGUARD_REQUIRE_JUDGE") != "" {
		t.Fatal("WIREGUARD_REQUIRE_JUDGE is set and wg(8) is not installed: the keys are made by the reference implementation in this lane")
	}
	if py, err := exec.LookPath("python3"); err == nil {
		out, err := exec.Command(py, "-c", `
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
for _ in range(int(__import__("sys").argv[1])):
    k = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print(base64.b64encode(k).decode())
`, "50").Output()
		if err == nil {
			return strings.Fields(string(out))
		}
	}
	t.Skip("neither wg(8) nor python3 with cryptography here; the CI lane installs wg")
	return nil
}

func TestKeysFromTheReferenceImplementationParse(t *testing.T) {
	keys := judgeKeys(t, 50)
	if len(keys) < 10 {
		t.Fatalf("the judge made %d keys", len(keys))
	}
	for _, s := range keys {
		k, err := ParseKey(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if k.String() != s {
			t.Fatalf("%q printed back as %q", s, k)
		}
	}
}

// The points of low order on Curve25519, as libsodium lists them in
// crypto_scalarmult/curve25519/ref10 (has_small_order), and each with the
// top bit set, which X25519 ignores (RFC 7748 5): every one must be refused.
func TestALowOrderKeyIsRefused(t *testing.T) {
	for _, h := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	} {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		for _, top := range []byte{0, 0x80} {
			c := append([]byte(nil), b...)
			c[31] |= top
			if _, err := ParseKey(base64.StdEncoding.EncodeToString(c)); err == nil || !strings.Contains(err.Error(), "low order") {
				t.Errorf("%x: %v", c, err)
			}
		}
	}
}

// One key, one spelling.
func TestOnlyTheCanonicalSpellingParses(t *testing.T) {
	good := "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
	if _, err := ParseKey(good); err != nil {
		t.Fatalf("%q: %v", good, err)
	}
	for _, bad := range []string{
		"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykx=", // stray bits in the last character
		"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw",  // no padding
		"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\n",
		" HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
		"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=" + "AAAA", // too long
		"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8",              // too short
		"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8yk-=",          // URL alphabet
		"",
	} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
