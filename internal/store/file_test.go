package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vouchsafe.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s, path
}

func TestAddAndFindByID(t *testing.T) {
	s, _ := newTestStore(t)
	c := Credential{
		ID:        []byte{0x01, 0x02, 0x03},
		Username:  "alice",
		PublicKey: []byte{0xa1, 0x01, 0x02},
		Algorithm: -7,
		SignCount: 1,
		AAGUID:    bytes.Repeat([]byte{0xaa}, 16),
	}
	if err := s.AddCredential(c); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	got, ok, err := s.FindByID(c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if !ok {
		t.Fatalf("FindByID: not found")
	}
	if got.Username != "alice" || got.Algorithm != -7 || got.SignCount != 1 {
		t.Fatalf("got %+v", got)
	}
	if !bytes.Equal(got.PublicKey, c.PublicKey) || !bytes.Equal(got.AAGUID, c.AAGUID) {
		t.Fatalf("byte fields mismatch: %+v", got)
	}
	if got.CreatedAt.IsZero() {
		t.Fatalf("CreatedAt not populated")
	}
}

func TestFindByID_NotFound(t *testing.T) {
	s, _ := newTestStore(t)
	_, ok, err := s.FindByID([]byte{0x99})
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if ok {
		t.Fatalf("expected not found")
	}
}

func TestAddCredential_RejectsDuplicateID(t *testing.T) {
	s, _ := newTestStore(t)
	c := Credential{ID: []byte{0x01}, Username: "alice"}
	if err := s.AddCredential(c); err != nil {
		t.Fatalf("first AddCredential: %v", err)
	}
	if err := s.AddCredential(c); err == nil {
		t.Fatalf("expected an error registering the same credential ID twice")
	}
}

func TestFindByUsername(t *testing.T) {
	s, _ := newTestStore(t)
	must(t, s.AddCredential(Credential{ID: []byte{0x01}, Username: "alice"}))
	must(t, s.AddCredential(Credential{ID: []byte{0x02}, Username: "alice"}))
	must(t, s.AddCredential(Credential{ID: []byte{0x03}, Username: "bob"}))

	alice, err := s.FindByUsername("alice")
	if err != nil {
		t.Fatalf("FindByUsername: %v", err)
	}
	if len(alice) != 2 {
		t.Fatalf("got %d credentials for alice, want 2", len(alice))
	}

	bob, err := s.FindByUsername("bob")
	if err != nil {
		t.Fatalf("FindByUsername: %v", err)
	}
	if len(bob) != 1 {
		t.Fatalf("got %d credentials for bob, want 1", len(bob))
	}

	nobody, err := s.FindByUsername("nobody")
	if err != nil || len(nobody) != 0 {
		t.Fatalf("got %v err=%v, want empty", nobody, err)
	}
}

func TestUpdateSignCount(t *testing.T) {
	s, _ := newTestStore(t)
	id := []byte{0x01}
	must(t, s.AddCredential(Credential{ID: id, Username: "alice", SignCount: 1}))

	if err := s.UpdateSignCount(id, 5); err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}
	got, ok, err := s.FindByID(id)
	if err != nil || !ok {
		t.Fatalf("FindByID: ok=%v err=%v", ok, err)
	}
	if got.SignCount != 5 {
		t.Fatalf("SignCount = %d, want 5", got.SignCount)
	}
}

func TestUpdateSignCount_NotFound(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.UpdateSignCount([]byte{0xff}, 1); err == nil {
		t.Fatalf("expected an error updating a credential that doesn't exist")
	}
}

func TestLoad_EmptyWhenFileMissing(t *testing.T) {
	s, _ := newTestStore(t)
	creds, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("got %d credentials, want 0", len(creds))
	}
}

func TestPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vouchsafe.json")
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	must(t, s1.AddCredential(Credential{ID: []byte{0x01}, Username: "alice"}))

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	got, ok, err := s2.FindByID([]byte{0x01})
	if err != nil || !ok {
		t.Fatalf("FindByID after reopen: ok=%v err=%v", ok, err)
	}
	if got.Username != "alice" {
		t.Fatalf("got %+v", got)
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits don't apply on Windows")
	}
	s, path := newTestStore(t)
	must(t, s.AddCredential(Credential{ID: []byte{0x01}, Username: "alice"}))

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 0600", perm)
	}
}

func TestOpen_RefusesInsecurePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits don't apply on Windows")
	}
	path := filepath.Join(t.TempDir(), "vouchsafe.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Open(path); err == nil {
		t.Fatalf("expected Open to refuse a group/world-readable store file")
	}
}

func TestNoLeftoverTempFiles(t *testing.T) {
	s, path := newTestStore(t)
	for i := range 5 {
		must(t, s.AddCredential(Credential{ID: []byte{byte(i)}, Username: "alice"}))
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Fatalf("unexpected leftover file: %s", e.Name())
		}
	}
}

func TestConcurrentAdds(t *testing.T) {
	s, _ := newTestStore(t)
	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.AddCredential(Credential{
				ID:       fmt.Appendf(nil, "cred-%02d", i),
				Username: "alice",
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("AddCredential(%d): %v", i, err)
		}
	}

	creds, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(creds) != n {
		t.Fatalf("got %d credentials, want %d", len(creds), n)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
