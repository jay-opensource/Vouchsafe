// Package e2e drives the actual compiled vouchsafe binary as a
// subprocess over real HTTP — the most literal possible proof that
// `go build ./cmd/vouchsafe && vouchsafe serve` produces a working
// server, not just that the in-process ceremony/httpapi packages agree
// with each other.
package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/webauthntest"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	return filepath.Join(wd, "..", "..")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func buildBinary(t *testing.T) string {
	t.Helper()
	name := "vouchsafe-e2e-test"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binPath := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/vouchsafe")
	cmd.Dir = moduleRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/vouchsafe: %v\n%s", err, out)
	}
	return binPath
}

func waitForReady(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/demo")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready in time", base)
}

func postJSON(t *testing.T, url string, body any) (*http.Response, map[string]any) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if resp.ContentLength != 0 || resp.StatusCode != http.StatusNoContent {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp, out
}

func testRealBinaryRegisterAndLogin(t *testing.T, alg int64) {
	if testing.Short() {
		t.Skip("skipping real-binary e2e test in -short mode")
	}
	binPath := buildBinary(t)
	port := freePort(t)
	storePath := filepath.Join(t.TempDir(), "vouchsafe.json")
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	base := "http://" + addr
	const rpID = "127.0.0.1" // what --rp-id derives to from --origin=base, per parseServeFlags

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "serve", "--listen", addr, "--store", storePath, "--origin", base)
	cmd.Stdout = os.Stderr // surface the server's own banner/log lines if the test fails
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start vouchsafe: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	waitForReady(t, base)

	username := "alice"

	beginResp, beginData := postJSON(t, base+"/register/begin", map[string]string{"username": username})
	if beginResp.StatusCode != http.StatusOK {
		t.Fatalf("register/begin status = %d", beginResp.StatusCode)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(beginData["challenge"].(string))
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}

	va, err := webauthntest.New(alg)
	if err != nil {
		t.Fatalf("New authenticator: %v", err)
	}
	credID := []byte{0x01, 0x02, 0x03, 0x04}
	reg, err := va.Register(rpID, base, challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}

	finishResp, _ := postJSON(t, base+"/register/finish", map[string]string{
		"username":          username,
		"rawId":             base64.RawURLEncoding.EncodeToString(credID),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(reg.ClientDataJSON),
		"attestationObject": base64.RawURLEncoding.EncodeToString(reg.AttestationObject),
	})
	if finishResp.StatusCode != http.StatusNoContent {
		t.Fatalf("register/finish status = %d", finishResp.StatusCode)
	}

	loginBeginResp, loginBeginData := postJSON(t, base+"/login/begin", map[string]string{"username": username})
	if loginBeginResp.StatusCode != http.StatusOK {
		t.Fatalf("login/begin status = %d", loginBeginResp.StatusCode)
	}
	loginChallenge, err := base64.RawURLEncoding.DecodeString(loginBeginData["challenge"].(string))
	if err != nil {
		t.Fatalf("decode login challenge: %v", err)
	}

	assertion, err := va.Authenticate(rpID, base, loginChallenge, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	loginFinishResp, loginFinishData := postJSON(t, base+"/login/finish", map[string]string{
		"username":          username,
		"rawId":             base64.RawURLEncoding.EncodeToString(credID),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(assertion.ClientDataJSON),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(assertion.AuthenticatorData),
		"signature":         base64.RawURLEncoding.EncodeToString(assertion.Signature),
	})
	if loginFinishResp.StatusCode != http.StatusOK {
		t.Fatalf("login/finish status = %d, body = %v", loginFinishResp.StatusCode, loginFinishData)
	}
	if loginFinishData["user"] != username {
		t.Fatalf("user = %v, want %s", loginFinishData["user"], username)
	}
	if tok, _ := loginFinishData["token"].(string); tok == "" {
		t.Fatalf("no session token returned")
	}
}

func TestE2E_RealBinary_RegisterAndLogin_ES256(t *testing.T) {
	testRealBinaryRegisterAndLogin(t, cose.AlgES256)
}

func TestE2E_RealBinary_RegisterAndLogin_RS256(t *testing.T) {
	testRealBinaryRegisterAndLogin(t, cose.AlgRS256)
}

func TestE2E_RealBinary_RegisterAndLogin_EdDSA(t *testing.T) {
	testRealBinaryRegisterAndLogin(t, cose.AlgEdDSA)
}
