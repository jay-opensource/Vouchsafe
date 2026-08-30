package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay-opensource/Vouchsafe/internal/ceremony"
	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/policy"
	"github.com/jay-opensource/Vouchsafe/internal/session"
	"github.com/jay-opensource/Vouchsafe/internal/store"
	"github.com/jay-opensource/Vouchsafe/internal/webauthntest"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

func newTestHTTPServer(t *testing.T) (*httptest.Server, *session.Signer) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "vouchsafe.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	challenges := ceremony.NewChallengeStore()
	origins := policy.NewOriginAllowlist(testOrigin)
	signer, err := session.NewSigner([]byte("01234567890123456789012345678901"), time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	s := &Server{
		Registrar:     &ceremony.Registrar{Challenges: challenges, Origins: origins, Store: st, RPID: testRPID, UVPolicy: policy.UVPreferred},
		Authenticator: &ceremony.Authenticator{Challenges: challenges, Origins: origins, Store: st, RPID: testRPID, UVPolicy: policy.UVPreferred},
		Store:         st,
		Sessions:      signer,
		RPID:          testRPID,
		RPName:        "vouchsafe test",
	}
	return httptest.NewServer(s.Routes()), signer
}

func postJSON(t *testing.T, ts *httptest.Server, path string, body any) (*http.Response, map[string]any) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if resp.ContentLength != 0 || resp.StatusCode != http.StatusNoContent {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp, out
}

func testFullFlow(t *testing.T, alg int64) {
	t.Helper()
	ts, signer := newTestHTTPServer(t)
	defer ts.Close()

	username := "alice"

	// --- registration ---
	beginResp, beginData := postJSON(t, ts, "/register/begin", map[string]string{"username": username})
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
	credID := make([]byte, 16)
	credID[0] = 0x01
	reg, err := va.Register(testRPID, testOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}

	finishResp, _ := postJSON(t, ts, "/register/finish", map[string]string{
		"username":          username,
		"rawId":             base64.RawURLEncoding.EncodeToString(credID),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(reg.ClientDataJSON),
		"attestationObject": base64.RawURLEncoding.EncodeToString(reg.AttestationObject),
	})
	if finishResp.StatusCode != http.StatusNoContent {
		t.Fatalf("register/finish status = %d", finishResp.StatusCode)
	}

	// --- login ---
	loginBeginResp, loginBeginData := postJSON(t, ts, "/login/begin", map[string]string{"username": username})
	if loginBeginResp.StatusCode != http.StatusOK {
		t.Fatalf("login/begin status = %d", loginBeginResp.StatusCode)
	}
	allow, ok := loginBeginData["allowCredentials"].([]any)
	if !ok || len(allow) != 1 {
		t.Fatalf("allowCredentials = %v, want exactly one entry", loginBeginData["allowCredentials"])
	}
	loginChallenge, err := base64.RawURLEncoding.DecodeString(loginBeginData["challenge"].(string))
	if err != nil {
		t.Fatalf("decode login challenge: %v", err)
	}

	assertion, err := va.Authenticate(testRPID, testOrigin, loginChallenge, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	loginFinishResp, loginFinishData := postJSON(t, ts, "/login/finish", map[string]string{
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
	token, _ := loginFinishData["token"].(string)
	if token == "" {
		t.Fatalf("no token returned")
	}
	claims, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("Verify issued token: %v", err)
	}
	if claims.Username != username {
		t.Fatalf("token username = %q, want %q", claims.Username, username)
	}
}

func TestFullFlow_ES256(t *testing.T) { testFullFlow(t, cose.AlgES256) }
func TestFullFlow_RS256(t *testing.T) { testFullFlow(t, cose.AlgRS256) }

func TestRegisterBegin_MissingUsername_BadRequest(t *testing.T) {
	ts, _ := newTestHTTPServer(t)
	defer ts.Close()
	resp, _ := postJSON(t, ts, "/register/begin", map[string]string{"username": ""})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRegisterFinish_InvalidBase64_BadRequest(t *testing.T) {
	ts, _ := newTestHTTPServer(t)
	defer ts.Close()
	resp, _ := postJSON(t, ts, "/register/finish", map[string]string{
		"username": "alice", "rawId": "not valid base64url!!!",
		"clientDataJSON": "also-not-valid!!!", "attestationObject": "still-not-valid!!!",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestLoginFinish_UnknownCredential_Unauthorized(t *testing.T) {
	ts, _ := newTestHTTPServer(t)
	defer ts.Close()

	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := []byte{0x99}
	beginResp, beginData := postJSON(t, ts, "/login/begin", map[string]string{"username": "nobody"})
	if beginResp.StatusCode != http.StatusOK {
		t.Fatalf("login/begin status = %d", beginResp.StatusCode)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(beginData["challenge"].(string))
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	assertion, err := va.Authenticate(testRPID, testOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}

	resp, _ := postJSON(t, ts, "/login/finish", map[string]string{
		"username": "nobody", "rawId": base64.RawURLEncoding.EncodeToString(credID),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(assertion.ClientDataJSON),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(assertion.AuthenticatorData),
		"signature":         base64.RawURLEncoding.EncodeToString(assertion.Signature),
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestDemoPage_Served(t *testing.T) {
	ts, _ := newTestHTTPServer(t)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/demo")
	if err != nil {
		t.Fatalf("GET /demo: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(buf.String(), testRPID) {
		t.Fatalf("demo page does not mention the configured RPID")
	}
	if !strings.Contains(buf.String(), "navigator.credentials.create") {
		t.Fatalf("demo page does not call navigator.credentials.create")
	}
}
