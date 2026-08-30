// Package store is an atomic, file-backed credential store. It holds
// public keys only — no passwords, no password hashes, no shared
// secrets. The private key never leaves the authenticator, so stealing
// this entire file yields nothing an attacker can log in with.
package store

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Credential is a stored WebAuthn credential: a public key and the
// bookkeeping needed to verify future assertions against it.
type Credential struct {
	ID        []byte    `json:"id"`
	Username  string    `json:"username"`
	PublicKey []byte    `json:"public_key_cbor"` // raw COSE_Key CBOR; re-parsed via internal/cose on use
	Algorithm int64     `json:"algorithm"`
	SignCount uint32    `json:"sign_count"`
	AAGUID    []byte    `json:"aaguid"`
	CreatedAt time.Time `json:"created_at"`

	// Nickname is a caller-supplied, display-only label ("Touch ID on
	// MacBook", "YubiKey 5") — never used in any security decision.
	Nickname string `json:"nickname,omitempty"`
}

type document struct {
	Credentials map[string]Credential `json:"credentials"`
}

// Store is a single JSON file holding every credential, replaced
// atomically on every write. All access is serialized through an
// in-memory mutex, so concurrent HTTP handlers never race on the file.
type Store struct {
	path string
	mu   sync.Mutex
}

// Open opens (or prepares to create) the store at path. It refuses to
// start if an existing file is readable by anyone other than its owner
// — meaningful on POSIX systems; Windows has no equivalent group/other
// permission bits, so the check is skipped there.
func Open(path string) (*Store, error) {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("store: %s is readable by group or other (mode %o) — refusing to start", path, info.Mode().Perm())
		}
	case os.IsNotExist(err):
		// Created on first write.
	default:
		return nil, fmt.Errorf("store: stat %s: %w", path, err)
	}
	return &Store{path: path}, nil
}

// Load returns every stored credential. A missing file is not an error
// — it means the store is empty.
func (s *Store) Load() ([]Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

// FindByID returns the stored credential with the given ID.
func (s *Store) FindByID(id []byte) (Credential, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	creds, err := s.loadLocked()
	if err != nil {
		return Credential{}, false, err
	}
	key := credentialKey(id)
	for _, c := range creds {
		if credentialKey(c.ID) == key {
			return c, true, nil
		}
	}
	return Credential{}, false, nil
}

// FindByUsername returns every credential registered to username.
func (s *Store) FindByUsername(username string) ([]Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	creds, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	var out []Credential
	for _, c := range creds {
		if c.Username == username {
			out = append(out, c)
		}
	}
	return out, nil
}

// AddCredential stores a new credential. It fails if a credential with
// the same ID is already stored.
func (s *Store) AddCredential(c Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	creds, err := s.loadLocked()
	if err != nil {
		return err
	}
	key := credentialKey(c.ID)
	for _, existing := range creds {
		if credentialKey(existing.ID) == key {
			return fmt.Errorf("store: credential already registered")
		}
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	return s.saveLocked(append(creds, c))
}

// UpdateSignCount persists a credential's new signature counter after a
// successful authentication.
func (s *Store) UpdateSignCount(id []byte, newCount uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	creds, err := s.loadLocked()
	if err != nil {
		return err
	}
	key := credentialKey(id)
	found := false
	for i := range creds {
		if credentialKey(creds[i].ID) == key {
			creds[i].SignCount = newCount
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("store: credential not found")
	}
	return s.saveLocked(creds)
}

// DeleteCredential permanently removes a credential. Callers must
// authorize the request themselves before calling this — the store has
// no notion of who's asking, only what's stored.
func (s *Store) DeleteCredential(id []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	creds, err := s.loadLocked()
	if err != nil {
		return err
	}
	key := credentialKey(id)
	out := make([]Credential, 0, len(creds))
	found := false
	for _, c := range creds {
		if credentialKey(c.ID) == key {
			found = true
			continue
		}
		out = append(out, c)
	}
	if !found {
		return fmt.Errorf("store: credential not found")
	}
	return s.saveLocked(out)
}

func (s *Store) loadLocked() ([]Credential, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read %s: %w", s.path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("store: parse %s: %w", s.path, err)
	}
	out := make([]Credential, 0, len(doc.Credentials))
	for _, c := range doc.Credentials {
		out = append(out, c)
	}
	return out, nil
}

// saveLocked atomically replaces the entire store contents: write to a
// temporary file in the same directory, fsync, then rename over the
// original. A crash at any point before the rename leaves the original
// file untouched.
func (s *Store) saveLocked(creds []Credential) error {
	doc := document{Credentials: make(map[string]Credential, len(creds))}
	for _, c := range creds {
		doc.Credentials[credentialKey(c.ID)] = c
	}
	data, err := json.MarshalIndent(&doc, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode: %w", err)
	}

	dir := filepath.Dir(s.path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: create directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".vouchsafe-*.tmp")
	if err != nil {
		return fmt.Errorf("store: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("store: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("store: fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("store: rename into place: %w", err)
	}
	return nil
}

func credentialKey(id []byte) string {
	return base64.StdEncoding.EncodeToString(id)
}
