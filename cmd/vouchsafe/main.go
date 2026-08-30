// Command vouchsafe is a WebAuthn (passkey) relying-party server with
// an empty dependency file — see STDLIB.md for what that replaces.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jay-opensource/Vouchsafe/internal/ceremony"
	"github.com/jay-opensource/Vouchsafe/internal/httpapi"
	"github.com/jay-opensource/Vouchsafe/internal/policy"
	"github.com/jay-opensource/Vouchsafe/internal/session"
	"github.com/jay-opensource/Vouchsafe/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vouchsafe serve [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "vouchsafe:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "vouchsafe: unknown command %q\nusage: vouchsafe serve [flags]\n", os.Args[1])
		os.Exit(2)
	}
}

type originList []string

func (o *originList) String() string { return strings.Join(*o, ",") }
func (o *originList) Set(v string) error {
	*o = append(*o, v)
	return nil
}

type serveConfig struct {
	listen         string
	origins        []string
	rpID           string
	uvPolicy       policy.UVPolicy
	storePath      string
	sessionKeyPath string
}

// parseServeFlags parses and validates flags into a serveConfig without
// touching the filesystem or network, so it can be tested directly.
func parseServeFlags(args []string) (serveConfig, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	var origins originList
	fs.Var(&origins, "origin", "allowed origin (repeatable)")
	rpID := fs.String("rp-id", "", "relying party ID (default: host of the first --origin)")
	uv := fs.String("uv", "preferred", "user verification policy: required|preferred|discouraged")
	storePath := fs.String("store", "./vouchsafe.json", "credential store path")
	sessionKeyPath := fs.String("session-key", "", "path to a file holding the session-signing key (generated on first run if absent)")
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, err
	}

	if len(origins) == 0 {
		origins = originList{"http://" + *listen}
	}
	resolvedRPID := *rpID
	if resolvedRPID == "" {
		u, err := url.Parse(origins[0])
		if err != nil || u.Hostname() == "" {
			return serveConfig{}, fmt.Errorf("cannot derive --rp-id from origin %q, pass --rp-id explicitly", origins[0])
		}
		resolvedRPID = u.Hostname()
	}

	uvPolicy := policy.UVPolicy(normalizeUV(*uv))
	switch uvPolicy {
	case policy.UVRequired, policy.UVPreferred, policy.UVDiscouraged:
	default:
		return serveConfig{}, fmt.Errorf("invalid --uv value %q: must be required, preferred, or discouraged", *uv)
	}

	return serveConfig{
		listen:         *listen,
		origins:        origins,
		rpID:           resolvedRPID,
		uvPolicy:       uvPolicy,
		storePath:      *storePath,
		sessionKeyPath: *sessionKeyPath,
	}, nil
}

func normalizeUV(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func runServe(args []string) error {
	cfg, err := parseServeFlags(args)
	if err != nil {
		return err
	}

	st, err := store.Open(cfg.storePath)
	if err != nil {
		return err
	}
	sessionKey, err := loadOrCreateSessionKey(cfg.sessionKeyPath)
	if err != nil {
		return err
	}
	signer, err := session.NewSigner(sessionKey, 24*time.Hour)
	if err != nil {
		return err
	}

	challenges := ceremony.NewChallengeStore()
	allowlist := policy.NewOriginAllowlist(cfg.origins...)
	srv := &httpapi.Server{
		Registrar:     &ceremony.Registrar{Challenges: challenges, Origins: allowlist, Store: st, RPID: cfg.rpID, UVPolicy: cfg.uvPolicy},
		Authenticator: &ceremony.Authenticator{Challenges: challenges, Origins: allowlist, Store: st, RPID: cfg.rpID, UVPolicy: cfg.uvPolicy},
		Store:         st,
		Sessions:      signer,
		RPID:          cfg.rpID,
		RPName:        "vouchsafe",
		Log:           slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}

	fmt.Printf("vouchsafe  origin=%s  rp_id=%s  uv=%s\n", strings.Join(cfg.origins, ","), cfg.rpID, cfg.uvPolicy)
	fmt.Printf("algorithms=ES256,RS256  attestation=none,packed  store=%s (0600)\n", cfg.storePath)
	if warn := loopbackWarning(cfg.listen); warn != "" {
		fmt.Println(warn)
	}

	return http.ListenAndServe(cfg.listen, srv.Routes())
}

// loopbackWarning returns a startup warning when listen isn't a loopback
// address — WebAuthn requires a secure context, and only localhost gets
// that for free over plain HTTP (W12; --tls mode is Tier 2).
func loopbackWarning(listen string) string {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return ""
	}
	return "[warn]  listen address is not loopback: browsers will refuse WebAuthn here unless the origin is HTTPS"
}

// loadOrCreateSessionKey loads the session-signing key from path,
// generating and persisting (mode 0600) a fresh 32-byte key on first
// run if the file doesn't exist. An empty path generates an ephemeral
// key that doesn't survive a restart — fine for a demo, not for
// anything meant to keep sessions valid across a redeploy.
func loadOrCreateSessionKey(path string) ([]byte, error) {
	if path == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate session key: %w", err)
		}
		return key, nil
	}

	data, err := os.ReadFile(path)
	if err == nil {
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read session key %s: %w", path, err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("write session key %s: %w", path, err)
	}
	return key, nil
}
