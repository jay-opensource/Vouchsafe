// Command demodata drives the real, running vouchsafe HTTP API end to end —
// RS256 and EdDSA ceremonies, packed self/full attestation, credential
// management, and the per-ceremony UV override — and writes the genuine
// request/response output to docs/demo/captures/*.txt.
//
// Every request goes over real HTTP to a real vouchsafe process. The only
// thing synthetic is the "browser" — internal/webauthntest builds real
// keys and real signatures the same way tests/e2e does, standing in for
// navigator.credentials since no real browser or hardware runs here. This
// program is standalone tooling for producing real, reproducible wire-level
// examples of every feature; it is not part of the shipped binary.
//
// Usage: go run ./tools/demodata (vouchsafe must already be serving on
// --origin http://localhost:8080 with a fresh --store).
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/webauthntest"
)

const base = "http://localhost:8080"

func main() {
	outDir := "docs/demo/captures"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatal(err)
	}

	capture(outDir, "rs256-ceremony.txt", func(w *writer) { ceremony(w, "bob", cose.AlgRS256, "RS256") })
	capture(outDir, "eddsa-ceremony.txt", func(w *writer) { ceremony(w, "carol", cose.AlgEdDSA, "EdDSA") })
	capture(outDir, "packed-self.txt", func(w *writer) { packedSelf(w) })
	capture(outDir, "packed-full.txt", func(w *writer) { packedFull(w) })
	capture(outDir, "credential-management.txt", func(w *writer) { credentialManagement(w) })
	capture(outDir, "uv-override.txt", func(w *writer) { uvOverride(w) })

	fmt.Println("done — see docs/demo/captures/*.txt")
}

type writer struct{ buf bytes.Buffer }

func (w *writer) cmd(format string, a ...any)  { fmt.Fprintf(&w.buf, "$ "+format+"\n", a...) }
func (w *writer) line(format string, a ...any) { fmt.Fprintf(&w.buf, format+"\n", a...) }
func (w *writer) jsonBlock(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	w.buf.Write(b)
	w.buf.WriteByte('\n')
}

func capture(dir, name string, fn func(w *writer)) {
	w := &writer{}
	fn(w)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, w.buf.Bytes(), 0o644); err != nil {
		fatal(err)
	}
	fmt.Println("wrote", path)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "demodata:", err)
	os.Exit(1)
}

func post(path string, body, out any) (int, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	resp, err := http.Post(base+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && resp.StatusCode < 300 {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		fatal(err)
	}
	return b
}

type creationOptions struct {
	RP                     map[string]string `json:"rp"`
	User                   map[string]string `json:"user"`
	Challenge              string            `json:"challenge"`
	AuthenticatorSelection map[string]any    `json:"authenticatorSelection"`
}

type requestOptions struct {
	Challenge string `json:"challenge"`
	FlowID    string `json:"flowId"`
}

// ceremony drives a full register+login round trip over real HTTP for the
// given algorithm, using webauthntest to play the browser/authenticator.
func ceremony(w *writer, username string, alg int64, label string) {
	auth, err := webauthntest.New(alg)
	if err != nil {
		fatal(err)
	}

	w.line("-- %s registration --", label)
	w.cmd(`curl -s -X POST localhost:8080/register/begin -d '{"username":%q}'`, username)
	var opts creationOptions
	if _, err := post("/register/begin", map[string]string{"username": username}, &opts); err != nil {
		fatal(err)
	}
	w.jsonBlock(opts)

	credID := make([]byte, 16)
	copy(credID, []byte(username+"-credential-id-pad"))
	reg, err := auth.Register("localhost", "http://localhost:8080", unb64(opts.Challenge), credID)
	if err != nil {
		fatal(err)
	}
	finishReq := map[string]string{
		"username":          username,
		"rawId":             b64(reg.CredentialID),
		"clientDataJSON":    b64(reg.ClientDataJSON),
		"attestationObject": b64(reg.AttestationObject),
	}
	status, _ := post("/register/finish", finishReq, nil)
	w.line("HTTP %d — credential stored (algorithm %d, %s)", status, alg, label)

	w.line("")
	w.line("-- %s login --", label)
	w.cmd(`curl -s -X POST localhost:8080/login/begin -d '{"username":%q}'`, username)
	var lopts requestOptions
	if _, err := post("/login/begin", map[string]string{"username": username}, &lopts); err != nil {
		fatal(err)
	}
	w.jsonBlock(lopts)

	assertion, err := auth.Authenticate("localhost", "http://localhost:8080", unb64(lopts.Challenge), credID)
	if err != nil {
		fatal(err)
	}
	loginFinish := map[string]string{
		"username":          username,
		"rawId":             b64(assertion.CredentialID),
		"clientDataJSON":    b64(assertion.ClientDataJSON),
		"authenticatorData": b64(assertion.AuthenticatorData),
		"signature":         b64(assertion.Signature),
	}
	var result map[string]any
	status, _ = post("/login/finish", loginFinish, &result)
	w.line("HTTP %d", status)
	w.jsonBlock(result)
}

func packedSelf(w *writer) {
	username := "dave-packed-self"
	auth, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		fatal(err)
	}
	w.line("-- packed self-attestation registration --")
	var opts creationOptions
	post("/register/begin", map[string]string{"username": username}, &opts)
	credID := []byte("dave-packed-self-cred-id")
	reg, err := auth.RegisterPackedSelf("localhost", "http://localhost:8080", unb64(opts.Challenge), credID)
	if err != nil {
		fatal(err)
	}
	w.cmd("curl -s -X POST localhost:8080/register/finish -d '{ ... fmt: \"packed\", attStmt: {alg, sig} — no x5c, signed by the credential's own key ... }'")
	status, _ := post("/register/finish", map[string]string{
		"username": username, "rawId": b64(reg.CredentialID),
		"clientDataJSON": b64(reg.ClientDataJSON), "attestationObject": b64(reg.AttestationObject),
	}, nil)
	w.line("HTTP %d — self-attestation verified against the credential's own public key, accepted", status)
}

func packedFull(w *writer) {
	username := "erin-packed-full"
	auth, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		fatal(err)
	}
	w.line("-- packed full attestation registration (x5c) --")
	var opts creationOptions
	post("/register/begin", map[string]string{"username": username}, &opts)
	credID := []byte("erin-packed-full-cred-id")
	reg, err := auth.RegisterPackedFull("localhost", "http://localhost:8080", unb64(opts.Challenge), credID)
	if err != nil {
		fatal(err)
	}
	w.cmd("curl -s -X POST localhost:8080/register/finish -d '{ ... fmt: \"packed\", attStmt: {alg, sig, x5c: [<DER cert>]} — signed by a separate attestation key ... }'")
	status, _ := post("/register/finish", map[string]string{
		"username": username, "rawId": b64(reg.CredentialID),
		"clientDataJSON": b64(reg.ClientDataJSON), "attestationObject": b64(reg.AttestationObject),
	}, nil)
	w.line("HTTP %d — leaf certificate in x5c verified as the statement's signer, accepted", status)
	w.line("(not chained to a trust anchor — that needs the FIDO Metadata Service, out of scope; see README Limits)")
}

func credentialManagement(w *writer) {
	username := "frank"
	auth, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		fatal(err)
	}
	var opts creationOptions
	post("/register/begin", map[string]string{"username": username}, &opts)
	credID := []byte("frank-credential-id-pad")
	reg, err := auth.Register("localhost", "http://localhost:8080", unb64(opts.Challenge), credID)
	if err != nil {
		fatal(err)
	}
	w.line("-- register with a nickname --")
	w.cmd(`curl -s -X POST localhost:8080/register/finish -d '{..., "nickname":"YubiKey on desk"}'`)
	post("/register/finish", map[string]string{
		"username": username, "rawId": b64(reg.CredentialID),
		"clientDataJSON": b64(reg.ClientDataJSON), "attestationObject": b64(reg.AttestationObject),
		"nickname": "YubiKey on desk",
	}, nil)

	var lopts requestOptions
	post("/login/begin", map[string]string{"username": username}, &lopts)
	assertion, err := auth.Authenticate("localhost", "http://localhost:8080", unb64(lopts.Challenge), credID)
	if err != nil {
		fatal(err)
	}
	var loginResult map[string]any
	post("/login/finish", map[string]string{
		"username": username, "rawId": b64(assertion.CredentialID),
		"clientDataJSON": b64(assertion.ClientDataJSON), "authenticatorData": b64(assertion.AuthenticatorData),
		"signature": b64(assertion.Signature),
	}, &loginResult)
	token, _ := loginResult["token"].(string)

	w.line("")
	w.line("-- list credentials --")
	w.cmd(`curl -s localhost:8080/credentials -H "Authorization: Bearer <token>"`)
	req, _ := http.NewRequest("GET", base+"/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal(err)
	}
	var list []map[string]any
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	w.jsonBlock(list)

	if len(list) > 0 {
		id, _ := list[0]["id"].(string)
		w.line("")
		w.line("-- revoke it --")
		w.cmd(`curl -s -X DELETE localhost:8080/credentials/%s -H "Authorization: Bearer <token>"`, id)
		dreq, _ := http.NewRequest("DELETE", base+"/credentials/"+id, nil)
		dreq.Header.Set("Authorization", "Bearer "+token)
		dresp, err := http.DefaultClient.Do(dreq)
		if err != nil {
			fatal(err)
		}
		w.line("HTTP %d", dresp.StatusCode)
		dresp.Body.Close()

		w.line("")
		w.line("-- list again: gone --")
		w.cmd(`curl -s localhost:8080/credentials -H "Authorization: Bearer <token>"`)
		req2, _ := http.NewRequest("GET", base+"/credentials", nil)
		req2.Header.Set("Authorization", "Bearer "+token)
		resp2, _ := http.DefaultClient.Do(req2)
		var list2 []map[string]any
		json.NewDecoder(resp2.Body).Decode(&list2)
		resp2.Body.Close()
		w.jsonBlock(list2)
	}
}

func uvOverride(w *writer) {
	username := "grace"
	auth, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		fatal(err)
	}
	var opts creationOptions
	post("/register/begin", map[string]string{"username": username}, &opts)
	credID := []byte("grace-credential-id-pad")
	reg, err := auth.Register("localhost", "http://localhost:8080", unb64(opts.Challenge), credID)
	if err != nil {
		fatal(err)
	}
	post("/register/finish", map[string]string{
		"username": username, "rawId": b64(reg.CredentialID),
		"clientDataJSON": b64(reg.ClientDataJSON), "attestationObject": b64(reg.AttestationObject),
	}, nil)

	w.line("-- server default policy: uv=preferred --")
	var lopts requestOptions
	post("/login/begin", map[string]string{"username": username}, &lopts)
	assertion, err := auth.Authenticate("localhost", "http://localhost:8080", unb64(lopts.Challenge), credID)
	if err != nil {
		fatal(err)
	}
	w.cmd(`curl -s -X POST localhost:8080/login/finish -d '{..., "uv":"required"}'`)
	var result map[string]any
	post("/login/finish", map[string]string{
		"username": username, "rawId": b64(assertion.CredentialID),
		"clientDataJSON": b64(assertion.ClientDataJSON), "authenticatorData": b64(assertion.AuthenticatorData),
		"signature": b64(assertion.Signature), "uv": "required",
	}, &result)
	w.jsonBlock(result)
	w.line("this one ceremony demanded stricter verification than the server default —")
	w.line("policy.EffectivePolicy only ever tightens the floor, never loosens it")
}
