// SPDX-License-Identifier: BSD-3-Clause

package wireguard

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-authn/harden/privfile"
)

// Floor is where a Source's ordering stood: the version and issue time of the
// newest list it took. A Source keeps it in memory; with
// [SourceConfig.FloorFile] it also keeps it across a restart, so that a
// replayed older list -- still signed, still unexpired, and naming a key since
// taken back -- is refused by a gateway that has just started.
//
// The floor is read WITHOUT trust: a file anyone with write access to the state
// directory could edit. That is safe for the reason go-authn/revocation's Floor
// is: nothing it says is used to admit anything, it only refuses lists below
// it, so a forged floor can only make the gateway refuse more (remove the file
// if the provider's versions restarted).
type Floor struct {
	Version  uint64
	IssuedAt time.Time
}

const floorMagic = "wireguard-floor 1"

// String is the floor as FloorFile keeps it: "<version> <issued, unix seconds>".
func (f Floor) String() string {
	return strconv.FormatUint(f.Version, 10) + " " + strconv.FormatInt(f.IssuedAt.Unix(), 10)
}

// ParseFloor reads what String wrote.
func ParseFloor(s string) (Floor, error) {
	v, iat, ok := strings.Cut(strings.TrimSpace(s), " ")
	if !ok {
		return Floor{}, fmt.Errorf("wireguard: a floor is a version and an issue time, not %q", s)
	}
	ver, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return Floor{}, fmt.Errorf("wireguard: the floor's version: %w", err)
	}
	sec, err := strconv.ParseInt(iat, 10, 64)
	if err != nil {
		return Floor{}, fmt.Errorf("wireguard: the floor's issue time: %w", err)
	}
	return Floor{Version: ver, IssuedAt: time.Unix(sec, 0)}, nil
}

// admits reports whether a list at version, issued at iat, may follow f: a
// newer version, or the same version issued no earlier.
func (f Floor) admits(version uint64, iat time.Time) bool {
	if version != f.Version {
		return version > f.Version
	}
	return iat.Unix() >= f.IssuedAt.Unix()
}

// ErrFloorNotKept is returned together with a good list when the floor could
// not be written to FloorFile: the list is valid and in use, but a restart
// before the next successful write would forget how far the gateway had got.
var ErrFloorNotKept = errors.New("wireguard: the floor could not be kept")

// loadFloor reads FloorFile; a file that is not there is no floor, one that is
// there and unreadable is an error (a floor that silently vanishes is a guard
// that silently vanishes).
func loadFloor(path string) (Floor, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Floor{}, false, nil
	}
	if err != nil {
		return Floor{}, false, fmt.Errorf("wireguard: the floor file: %w", err)
	}
	rest, ok := strings.CutPrefix(string(b), floorMagic+"\n")
	if !ok {
		return Floor{}, false, fmt.Errorf("wireguard: %s is not a floor file (remove it if the provider's versions restarted)", path)
	}
	f, err := ParseFloor(rest)
	if err != nil {
		return Floor{}, false, fmt.Errorf("%w: %s (remove it if it is damaged)", err, path)
	}
	return f, true, nil
}

// keepFloor writes the floor in one rename, so a crash leaves the old file or
// the new one, never half of one.
//
// The file is written by go-authn/harden's privfile: owner-only, in a directory
// only its owner can write.
func keepFloor(path string, f Floor) error {
	return privfile.Write(path, []byte(floorMagic+"\n"+f.String()+"\n"))
}
