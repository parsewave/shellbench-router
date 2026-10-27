package tokens

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"
)

// Update applies fn to the token file at path under an exclusive lock, then
// writes the result atomically. The lock (a sidecar "<path>.lock") serialises
// the CLI and the admin API, which may run in different containers sharing
// the volume, so concurrent changes are never lost. A missing file starts
// empty when create is true. If fn returns an error nothing is written.
func Update(path string, create bool, fn func(*File) error) error {
	unlock, err := lockFile(path + ".lock")
	if err != nil {
		return fmt.Errorf("lock %s: %w", path, err)
	}
	defer unlock()
	f, err := Read(path)
	if errors.Is(err, fs.ErrNotExist) && create {
		f, err = &File{Version: 1}, nil
	}
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		return err
	}
	return Write(path, f)
}

func lockFile(path string) (func(), error) {
	lf, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := flock(lf); err != nil {
		lf.Close()
		return nil, err
	}
	return func() { lf.Close() }, nil // closing releases the lock
}

// ParseModels parses a comma-separated allow-list; "*" or empty means all.
func ParseModels(s string) []string {
	var out []string
	for _, m := range strings.Split(s, ",") {
		if m = strings.TrimSpace(m); m != "" {
			if m == "*" {
				return nil
			}
			out = append(out, m)
		}
	}
	return out
}

// ParseExpiry accepts a duration from now (90d, 12h), a date (2027-01-31),
// RFC3339, or "never"/"" (no expiry).
func ParseExpiry(s string, now time.Time) (*time.Time, error) {
	switch s = strings.TrimSpace(s); s {
	case "", "never":
		return nil, nil
	}
	if d, err := ParseDuration(s); err == nil {
		t := now.UTC().Add(d).Truncate(time.Second)
		return &t, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t, nil
		}
	}
	return nil, fmt.Errorf("cannot parse expiry %q (want 90d, 12h, 2027-01-31, RFC3339, or never)", s)
}

// ParseDuration extends time.ParseDuration with a "d" (day) suffix.
func ParseDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}
