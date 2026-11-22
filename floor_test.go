package wireguard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func floorSource(t *testing.T, p *provider, file string) (*Source, error) {
	t.Helper()
	return NewSource(context.Background(), SourceConfig{Issuer: p.srv.URL, ClientID: "gw", ClientSecret: "s3cret", FloorFile: file})
}

// The audit's suspicion, as a test: a restart forgot the floor. With a
// FloorFile a new Source refuses what the old one would have.
func TestARestartKeepsTheFloor(t *testing.T) {
	p := newProvider(t)
	version := uint64(5)
	p.list = func(iss string) (map[string]any, map[string]any) {
		return listHeader(), sampleList(version, Peer{Key: mustKey(t, keyA), Subject: "a", Expires: time.Now().Add(time.Hour)}).Claims(iss, "gw")
	}
	file := filepath.Join(t.TempDir(), "floor")
	s, err := floorSource(t, p, file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	// restart
	s2, err := floorSource(t, p, file)
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := s2.Floor(); !ok || f.Version != 5 {
		t.Fatalf("floor after restart = %v, %v", f, ok)
	}
	version = 4
	if _, err := s2.Fetch(context.Background()); !errors.Is(err, errRolledBack) {
		t.Errorf("version 4 after a restart at 5: %v", err)
	}
	version = 5
	if _, err := s2.Fetch(context.Background()); err != nil {
		t.Errorf("the same version after a restart: %v", err)
	}
	version = 6
	if _, err := s2.Fetch(context.Background()); err != nil {
		t.Errorf("a newer version after a restart: %v", err)
	}
	s3, _ := floorSource(t, p, file)
	if f, _ := s3.Floor(); f.Version != 6 {
		t.Errorf("the floor did not move up on disk: %v", f)
	}
}

// Without a FloorFile nothing is kept (the documented memory-only behaviour).
func TestNoFloorFileNoFloor(t *testing.T) {
	p := newProvider(t)
	p.list = func(iss string) (map[string]any, map[string]any) {
		return listHeader(), sampleList(5).Claims(iss, "gw")
	}
	s, _ := floorSource(t, p, "")
	if _, ok := s.Floor(); ok {
		t.Error("a floor before any list")
	}
	if _, err := s.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f, ok := s.Floor(); !ok || f.Version != 5 {
		t.Errorf("Floor() = %v, %v", f, ok)
	}
}

// The same version issued earlier is an older list, too.
func TestSameVersionIssuedEarlierIsRefused(t *testing.T) {
	p := newProvider(t)
	iat := time.Now().Add(-time.Minute)
	p.list = func(iss string) (map[string]any, map[string]any) {
		l := sampleList(5)
		l.IssuedAt = iat
		return listHeader(), l.Claims(iss, "gw")
	}
	s, _ := floorSource(t, p, "")
	if _, err := s.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	iat = iat.Add(-time.Hour)
	if _, err := s.Fetch(context.Background()); !errors.Is(err, errRolledBack) {
		t.Errorf("version 5 issued an hour earlier: %v", err)
	}
	iat = iat.Add(2 * time.Hour)
	if _, err := s.Fetch(context.Background()); err != nil {
		t.Errorf("version 5 re-issued later: %v", err)
	}
}

// A floor file that is there but wrong is an error: a guard that silently
// vanishes is no guard.
func TestADamagedFloorFileIsRefused(t *testing.T) {
	p := newProvider(t)
	dir := t.TempDir()
	for name, content := range map[string]string{
		"nomagic":    "5 100\n",
		"badversion": floorMagic + "\nx 100\n",
		"badtime":    floorMagic + "\n5 y\n",
		"noparts":    floorMagic + "\n5\n",
		"empty":      "",
	} {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := floorSource(t, p, file); err == nil {
			t.Errorf("%s: a damaged floor file was accepted", name)
		}
	}
	// A directory where the file should be is unreadable, not absent.
	// (The wording of the error is the platform's.)
	if _, err := floorSource(t, p, dir); err == nil {
		t.Error("a directory as the floor file was accepted")
	}
	// Absent is fine: first start.
	if _, err := floorSource(t, p, filepath.Join(dir, "absent")); err != nil {
		t.Errorf("absent floor file: %v", err)
	}
}

// A floor that cannot be written does not hold back a good list, and says so.
func TestAFloorThatCannotBeKeptIsReported(t *testing.T) {
	p := newProvider(t)
	p.list = func(iss string) (map[string]any, map[string]any) {
		return listHeader(), sampleList(5).Claims(iss, "gw")
	}
	s, err := floorSource(t, p, filepath.Join(t.TempDir(), "no-such-dir", "floor"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := s.Fetch(context.Background())
	if l == nil || !errors.Is(err, ErrFloorNotKept) {
		t.Errorf("list %v, err %v", l, err)
	}
	if f, _ := s.Floor(); f.Version != 5 {
		t.Errorf("the in-memory floor must still move: %v", f)
	}
}

// The floor is written only when it moves: the same position again touches
// nothing, so a gateway polling every few seconds does not rewrite a file.
func TestTheSamePositionIsNotRewritten(t *testing.T) {
	p := newProvider(t)
	iat := time.Now().Add(-time.Minute)
	p.list = func(iss string) (map[string]any, map[string]any) {
		l := sampleList(5)
		l.IssuedAt = iat
		return listHeader(), l.Claims(iss, "gw")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := floorSource(t, p, filepath.Join(dir, "floor"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil { // a write now would fail
		t.Fatal(err)
	}
	if _, err := s.Fetch(context.Background()); err != nil {
		t.Errorf("the same position again tried to write: %v", err)
	}
}

// A rename that fails leaves no temporary file behind.
func TestAFailedRenameLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "floor")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := keepFloor(target, Floor{Version: 1, IssuedAt: time.Unix(1, 0)}); err == nil {
		t.Fatal("a directory was replaced by a file")
	}
	es, err := os.ReadDir(dir)
	if err != nil || len(es) != 1 {
		t.Errorf("entries %v, %v: want only the directory", es, err)
	}
}

func TestFloorRoundTrip(t *testing.T) {
	f := Floor{Version: 1<<63 + 7, IssuedAt: time.Unix(1700000000, 0)}
	g, err := ParseFloor(f.String())
	if err != nil || g.Version != f.Version || !g.IssuedAt.Equal(f.IssuedAt) {
		t.Errorf("%v -> %v, %v", f, g, err)
	}
	for _, bad := range []string{"", "5", "x 1", "1 x", "-1 5", "18446744073709551616 5"} {
		if _, err := ParseFloor(bad); err == nil {
			t.Errorf("ParseFloor(%q) accepted", bad)
		}
	}
	if _, err := ParseFloor("5"); err == nil || !strings.Contains(err.Error(), "a version and an issue time") {
		t.Errorf("one field: %v", err)
	}
}

func TestFloorAdmits(t *testing.T) {
	f := Floor{Version: 5, IssuedAt: time.Unix(1000, 0)}
	for _, c := range []struct {
		v    uint64
		iat  int64
		want bool
	}{
		{4, 9999, false}, {5, 999, false}, {5, 1000, true}, {5, 1001, true}, {6, 1, true},
	} {
		if got := f.admits(c.v, time.Unix(c.iat, 0)); got != c.want {
			t.Errorf("admits(%d, %d) = %v", c.v, c.iat, got)
		}
	}
}
