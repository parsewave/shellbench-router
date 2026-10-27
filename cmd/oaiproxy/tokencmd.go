package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"oaiproxy/internal/tokens"
)

// tokenCmd implements "oaiproxy token ...". Tokens are printed to stdout
// (exactly once, at creation/rotation) and everything else to stderr, so
// `TOKEN=$(oaiproxy token add -id alice)` captures only the secret. Changes
// go through tokens.Update, so they never race the admin API or each other.
func tokenCmd(args []string, stdout, stderr io.Writer, now time.Time) error {
	if len(args) == 0 {
		return errors.New("token: missing subcommand (add, list, rotate, revoke, enable, set, remove, add-key, remove-key)")
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
	expires := flags.String("expires", "", "expiry: duration (90d, 12h), date (2027-01-31), RFC3339, or never")
	note := flags.String("note", "", "free-form note")
	grace := flags.String("grace", "0", "rotate: how long the old token stays valid (0 = revoke now)")
	pubkey := flags.String("pubkey", "", "add/add-key: the user's Ed25519 public key (ed25519:<base64> from `pxkey generate`, or PEM)")
	unsigned := flags.Bool("unsigned", false, "add: create a plain bearer token without request signing (for tools that can't sign)")
	keyID := flags.String("key-id", "", "remove-key: id of the signing key (see list)")
	allowUnsigned := flags.Bool("allow-unsigned", false, "remove-key: allow removing the last key, turning signing off")
	if err := flags.Parse(args); err != nil {
		return err
	}
	set := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if sub == "list" {
		f, err := tokens.Read(*file)
		if err != nil {
			return err
		}
		return listClients(stdout, f, now)
	}
	if *id == "" {
		return errors.New("-id is required")
	}
	apply := func(c *tokens.Client) error {
		if set["models"] {
			c.Models = tokens.ParseModels(*models)
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
		if set["expires"] && sub != "add-key" {
			t, err := tokens.ParseExpiry(*expires, now)
			if err != nil {
				return fmt.Errorf("-expires: %w", err)
			}
			c.ExpiresAt = t
		}
		return nil
	}
	find := func(f *tokens.File) (*tokens.Client, error) {
		if c := f.Find(*id); c != nil {
			return c, nil
		}
		return nil, fmt.Errorf("client %q %w", *id, tokens.ErrNotFound)
	}

	var tok, msg string
	err := tokens.Update(*file, sub == "add", func(f *tokens.File) error {
		switch sub {
		case "add":
			if *pubkey == "" && !*unsigned {
				return errSignedDefault
			}
			if *pubkey != "" && *unsigned {
				return errors.New("-pubkey and -unsigned are mutually exclusive")
			}
			nc := tokens.Client{ID: *id}
			if err := apply(&nc); err != nil {
				return err
			}
			var err error
			if tok, err = f.Add(nc, now); err != nil {
				return err
			}
			msg = fmt.Sprintf("Created client %q. Its token is printed below exactly once; store it securely.", *id)
			if *pubkey != "" {
				k, err := f.AddKey(*id, *pubkey, "", nil, now)
				if err != nil {
					return err
				}
				msg += fmt.Sprintf("\nSigning key %s registered: requests must be signed.", k.ID)
			} else {
				msg += "\nUnsigned: this token alone grants access, so treat it like a password."
			}
		case "rotate":
			g, err := tokens.ParseDuration(*grace)
			if err != nil {
				return fmt.Errorf("-grace: %w", err)
			}
			if tok, err = f.Rotate(*id, g, now); err != nil {
				return err
			}
			if g > 0 {
				msg = fmt.Sprintf("Rotated %q; previous token(s) remain valid for %s.", *id, g)
			} else {
				msg = fmt.Sprintf("Rotated %q; previous token(s) revoked.", *id)
			}
		case "revoke", "enable":
			c, err := find(f)
			if err != nil {
				return err
			}
			c.Disabled = sub == "revoke"
		case "set":
			c, err := find(f)
			if err != nil {
				return err
			}
			if err := apply(c); err != nil {
				return err
			}
		case "remove":
			return f.Remove(*id)
		case "add-key":
			if *pubkey == "" {
				return errors.New("-pubkey is required")
			}
			exp, err := tokens.ParseExpiry(*expires, now)
			if err != nil {
				return fmt.Errorf("-expires: %w", err)
			}
			k, err := f.AddKey(*id, *pubkey, *note, exp, now)
			if err != nil {
				return err
			}
			msg = fmt.Sprintf("Registered signing key %s for %q; its requests must now be signed.", k.ID, *id)
		case "remove-key":
			if *keyID == "" {
				return errors.New("-key-id is required")
			}
			if err := f.RemoveKey(*id, *keyID, *allowUnsigned); err != nil {
				return err
			}
		default:
			return fmt.Errorf("token: unknown subcommand %q", sub)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if msg == "" {
		msg = fmt.Sprintf("Updated %q (%s). The running server reloads within seconds.", *id, sub)
	}
	fmt.Fprintln(stderr, msg)
	if tok != "" {
		fmt.Fprintln(stdout, tok)
	}
	return nil
}

// errSignedDefault explains the default: tokens are tied to the user's key.
var errSignedDefault = errors.New("signed tokens are the default: pass -pubkey ed25519:... (the user gets it from `pxkey generate`), " +
	"or -unsigned for a plain bearer token (only for tools that can't sign)")

func listClients(stdout io.Writer, f *tokens.File, now time.Time) error {
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATUS\tMODELS\tRPM\tBURST\tCONCURRENCY\tEXPIRES\tSECRETS\tSIGNING KEYS")
	for _, c := range f.Clients {
		var hints, keys []string
		for _, s := range c.Secrets {
			h := s.Hint
			if s.ExpiresAt != nil {
				h += " (until " + s.ExpiresAt.Format(time.RFC3339) + ")"
			}
			hints = append(hints, h)
		}
		for _, k := range c.PublicKeys {
			kk := k.ID
			if k.ExpiresAt != nil {
				kk += " (until " + k.ExpiresAt.Format(time.RFC3339) + ")"
			}
			keys = append(keys, kk)
		}
		if len(keys) == 0 {
			keys = []string{"- (unsigned)"}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.ID, c.Status(now), orAll(c.Models), limit(c.RPM), limit(c.Burst), limit(c.MaxConcurrent), fmtTime(c.ExpiresAt), strings.Join(hints, ", "), strings.Join(keys, ", "))
	}
	return tw.Flush()
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
