package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"oaiproxy/internal/tokens"
)

// tokenCmd implements "oaiproxy token ...". Tokens are printed to stdout
// (exactly once, at creation/rotation) and everything else to stderr, so
// `TOKEN=$(oaiproxy token add -id alice)` captures only the secret.
func tokenCmd(args []string, stdout, stderr io.Writer, now time.Time) error {
	if len(args) == 0 {
		return errors.New("token: missing subcommand (add, list, rotate, revoke, enable, set, remove)")
	}
	sub, args := args[0], args[1:]
	flags := flag.NewFlagSet("token "+sub, flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", envOr("TOKENS_FILE", "tokens.json"), "token file `path`")
	id := flags.String("id", "", "client id (letters, digits, _ . -)")
	models := flags.String("models", "", "comma-separated allowed models; prefix* globs; empty or * = all")
	rpm := flags.Int("rpm", 0, "requests per minute (0 = unlimited)")
	burst := flags.Int("burst", 0, "rate-limit burst (0 = same as rpm)")
	conc := flags.Int("concurrency", 0, "max concurrent requests (0 = unlimited)")
	expires := flags.String("expires", "", "client expiry: duration (90d, 12h), date (2027-01-31), RFC3339, or never")
	note := flags.String("note", "", "free-form note")
	grace := flags.String("grace", "0", "rotate: how long the old token stays valid (0 = revoke now)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	set := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { set[f.Name] = true })

	f, err := tokens.Read(*file)
	if errors.Is(err, fs.ErrNotExist) && sub == "add" {
		f, err = &tokens.File{Version: 1}, nil
	}
	if err != nil {
		return err
	}
	if sub != "list" && *id == "" {
		return errors.New("-id is required")
	}

	var c *tokens.Client
	if sub != "list" && sub != "add" {
		if c = f.Find(*id); c == nil {
			return fmt.Errorf("client %q not found", *id)
		}
	}
	apply := func(c *tokens.Client) error {
		if set["models"] {
			c.Models = parseModels(*models)
		}
		if set["rpm"] {
			c.RPM = *rpm
		}
		if set["burst"] {
			c.Burst = *burst
		}
		if set["concurrency"] {
			c.MaxConcurrent = *conc
		}
		if set["note"] {
			c.Note = *note
		}
		if set["expires"] {
			t, err := parseExpiry(*expires, now)
			if err != nil {
				return err
			}
			c.ExpiresAt = t
		}
		return nil
	}

	switch sub {
	case "list":
		tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSTATUS\tMODELS\tRPM\tBURST\tCONCURRENCY\tEXPIRES\tSECRETS")
		for _, c := range f.Clients {
			var hints []string
			for _, s := range c.Secrets {
				h := s.Hint
				if s.ExpiresAt != nil {
					h += " (until " + s.ExpiresAt.Format(time.RFC3339) + ")"
				}
				hints = append(hints, h)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.ID, c.Status(now), orAll(c.Models), limit(c.RPM), limit(c.Burst), limit(c.MaxConcurrent), fmtTime(c.ExpiresAt), strings.Join(hints, ", "))
		}
		return tw.Flush()
	case "add":
		nc := tokens.Client{ID: *id}
		if err := apply(&nc); err != nil {
			return err
		}
		tok, err := f.Add(nc, now)
		if err != nil {
			return err
		}
		if err := tokens.Write(*file, f); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "Created client %q. Its token is printed below exactly once; store it securely.\n", *id)
		fmt.Fprintln(stdout, tok)
		return nil
	case "rotate":
		g, err := parseDuration(*grace)
		if err != nil {
			return fmt.Errorf("-grace: %w", err)
		}
		tok, err := f.Rotate(*id, g, now)
		if err != nil {
			return err
		}
		if err := tokens.Write(*file, f); err != nil {
			return err
		}
		if g > 0 {
			fmt.Fprintf(stderr, "Rotated %q; previous token(s) remain valid for %s.\n", *id, g)
		} else {
			fmt.Fprintf(stderr, "Rotated %q; previous token(s) revoked.\n", *id)
		}
		fmt.Fprintln(stdout, tok)
		return nil
	case "revoke", "enable":
		c.Disabled = sub == "revoke"
	case "set":
		if err := apply(c); err != nil {
			return err
		}
	case "remove":
		if err := f.Remove(*id); err != nil {
			return err
		}
	default:
		return fmt.Errorf("token: unknown subcommand %q", sub)
	}
	if err := tokens.Write(*file, f); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "Updated %q (%s). The running server reloads within seconds.\n", *id, sub)
	return nil
}

func parseModels(s string) []string {
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

func parseExpiry(s string, now time.Time) (*time.Time, error) {
	switch s = strings.TrimSpace(s); s {
	case "", "never":
		return nil, nil
	}
	if d, err := parseDuration(s); err == nil {
		t := now.UTC().Add(d).Truncate(time.Second)
		return &t, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t, nil
		}
	}
	return nil, fmt.Errorf("-expires: cannot parse %q", s)
}

// parseDuration extends time.ParseDuration with a "d" (day) suffix.
func parseDuration(s string) (time.Duration, error) {
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

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func orAll(m []string) string {
	if len(m) == 0 {
		return "*"
	}
	return strings.Join(m, ",")
}

func limit(n int) string {
	if n == 0 {
		return "-"
	}
	return strconv.Itoa(n)
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Format(time.RFC3339)
}
