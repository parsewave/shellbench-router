//go:build !unix

package tokens

import "os"

// flock is a no-op where advisory locks are unavailable; Write is still
// atomic, but concurrent updates may overwrite each other.
func flock(*os.File) error { return nil }
