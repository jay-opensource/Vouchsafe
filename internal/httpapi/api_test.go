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
func TestFullFlow_EdDSA(t *testing.T) { testFullFlow(t, cose.AlgEdDSA) }

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

func TestDiscoverableLogin_Success(t *testing.T) {
	ts, _ := newTestHTTPServer(t)
	defer ts.Close()

	username := "alice"
	beginResp, beginData := postJSON(t, ts, "/register/begin", map[string]string{"username": username})
	if beginResp.StatusCode != http.StatusOK {
		t.Fatalf("register/begin status = %d", beginResp.StatusCode)
	}
	regChallenge, err := base64.RawURLEncoding.DecodeString(beginData["challenge"].(string))
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New authenticator: %v", err)
	}
	credID := []byte{0x05, 0x06, 0x07, 0x08}
	reg, err := va.Register(testRPID, testOrigin, regChallenge, credID)
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

	// Discoverable begin: no username.
	loginBeginResp, loginBeginData := postJSON(t, ts, "/login/begin", map[string]string{})
	if loginBeginResp.StatusCode != http.StatusOK {
		t.Fatalf("login/begin status = %d", loginBeginResp.StatusCode)
	}
	if _, present := loginBeginData["allowCredentials"]; present {
		t.Fatalf("allowCredentials present for a discoverable begin, want omitted")
	}
	flowID, _ := loginBeginData["flowId"].(string)
	if flowID == "" {
		t.Fatalf("no flowId returned for a discoverable begin")
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
		"flowId":            flowID,
		"rawId":             base64.RawURLEncoding.EncodeToString(credID),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(assertion.ClientDataJSON),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(assertion.AuthenticatorData),
		"signature":         base64.RawURLEncoding.EncodeToString(assertion.Signature),
	})
	if loginFinishResp.StatusCode != http.StatusOK {
		t.Fatalf("login/finish status = %d, body = %v", loginFinishResp.StatusCode, loginFinishData)
	}
	if loginFinishData["user"] != username {
		t.Fatalf("user = %v, want %s — identity must resolve from the credential even in the discoverable flow", loginFinishData["user"], username)
	}
}

func TestDiscoverableLogin_WrongFlowIDRejected(t *testing.T) {
	ts, _ := newTestHTTPServer(t)
	defer ts.Close()

	loginBeginResp, _ := postJSON(t, ts, "/login/begin", map[string]string{})
	if loginBeginResp.StatusCode != http.StatusOK {
		t.Fatalf("login/begin status = %d", loginBeginResp.StatusCode)
	}

	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := []byte{0x01}
	assertion, err := va.Authenticate(testRPID, testOrigin, make([]byte, 32), credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}

	resp, _ := postJSON(t, ts, "/login/finish", map[string]string{
		"flowId":            "not-the-real-flow-id",
		"rawId":             base64.RawURLEncoding.EncodeToString(credID),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(assertion.ClientDataJSON),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(assertion.AuthenticatorData),
		"signature":         base64.RawURLEncoding.EncodeToString(assertion.Signature),
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// authedRequest sends method/path with an optional bearer token and
// optional JSON body, returning the response and its raw body bytes —
// callers decode the bytes themselves into whatever shape they expect,
// since the response body can only be read once and different callers
// here want different shapes (error maps, credentialSummary lists).
func authedRequest(t *testing.T, ts *httptest.Server, method, path, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, ts.URL+path, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	respBody := new(bytes.Buffer)
	if _, err := respBody.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp, respBody.Bytes()
}

func registerOneCredential(t *testing.T, ts *httptest.Server, username string) []byte {
	t.Helper()
	beginResp, beginData := postJSON(t, ts, "/register/begin", map[string]string{"username": username})
	if beginResp.StatusCode != http.StatusOK {
		t.Fatalf("register/begin status = %d", beginResp.StatusCode)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(beginData["challenge"].(string))
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New authenticator: %v", err)
	}
	credID := []byte{0x0a, 0x0b, 0x0c, 0x0d}
	reg, err := va.Register(testRPID, testOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}
	finishResp, _ := postJSON(t, ts, "/register/finish", map[string]string{
		"username":          username,
		"rawId":             base64.RawURLEncoding.EncodeToString(credID),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(reg.ClientDataJSON),
		"attestationObject": base64.RawURLEncoding.EncodeToString(reg.AttestationObject),
		"nickname":          "Test Authenticator",
	})
	if finishResp.StatusCode != http.StatusNoContent {
		t.Fatalf("register/finish status = %d", finishResp.StatusCode)
	}
	return credID
}

func TestListCredentials_Success(t *testing.T) {
	ts, signer := newTestHTTPServer(t)
	defer ts.Close()
	registerOneCredential(t, ts, "alice")

	token, err := signer.Issue("alice", true)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	resp, err := http.NewRequest(http.MethodGet, ts.URL+"/credentials", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(resp)
	if err != nil {
		t.Fatalf("GET /credentials: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	var list []credentialSummary
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d credentials, want 1", len(list))
	}
	if list[0].Nickname != "Test Authenticator" {
		t.Fatalf("Nickname = %q, want %q", list[0].Nickname, "Test Authenticator")
	}
}

func TestListCredentials_Unauthorized(t *testing.T) {
	ts, _ := newTestHTTPServer(t)
	defer ts.Close()
	resp, _ := authedRequest(t, ts, http.MethodGet, "/credentials", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestDeleteCredential_Success(t *testing.T) {
	ts, signer := newTestHTTPServer(t)
	defer ts.Close()
	credID := registerOneCredential(t, ts, "alice")

	token, err := signer.Issue("alice", true)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	resp, _ := authedRequest(t, ts, http.MethodDelete, "/credentials/"+base64.RawURLEncoding.EncodeToString(credID), token, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	// Deleted credential must actually be gone: a login attempt now fails.
	_, listBody := authedRequest(t, ts, http.MethodGet, "/credentials", token, nil)
	var list []credentialSummary
	if err := json.Unmarshal(listBody, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("got %d credentials after delete, want 0", len(list))
	}
}

func TestDeleteCredential_Unauthorized(t *testing.T) {
	ts, _ := newTestHTTPServer(t)
	defer ts.Close()
	credID := registerOneCredential(t, ts, "alice")

	resp, _ := authedRequest(t, ts, http.MethodDelete, "/credentials/"+base64.RawURLEncoding.EncodeToString(credID), "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestDeleteCredential_NotOwnerRejected(t *testing.T) {
	ts, signer := newTestHTTPServer(t)
	defer ts.Close()
	aliceCredID := registerOneCredential(t, ts, "alice")

	bobToken, err := signer.Issue("bob", true)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	resp, _ := authedRequest(t, ts, http.MethodDelete, "/credentials/"+base64.RawURLEncoding.EncodeToString(aliceCredID), bobToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (bob must not be able to delete alice's credential)", resp.StatusCode)
	}

	// alice's credential must be untouched.
	aliceToken, err := signer.Issue("alice", true)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, listBody := authedRequest(t, ts, http.MethodGet, "/credentials", aliceToken, nil)
	var list []credentialSummary
	if err := json.Unmarshal(listBody, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("alice's credential count = %d after bob's failed delete attempt, want 1", len(list))
	}
}

func TestDeleteCredential_NotFound(t *testing.T) {
	ts, signer := newTestHTTPServer(t)
	defer ts.Close()
	token, err := signer.Issue("alice", true)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	resp, _ := authedRequest(t, ts, http.MethodDelete, "/credentials/"+base64.RawURLEncoding.EncodeToString([]byte{0xff, 0xff}), token, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
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
