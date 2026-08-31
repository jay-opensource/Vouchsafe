// Package httpapi is the HTTP transport for vouchsafe's two ceremonies:
// decode/encode JSON and base64url at the boundary, delegate everything
// security-relevant to internal/ceremony. Any failure gets a generic
// message on the wire and a specific one in the log (spec §7.1).
package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jay-opensource/Vouchsafe/internal/ceremony"
	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/policy"
	"github.com/jay-opensource/Vouchsafe/internal/session"
	"github.com/jay-opensource/Vouchsafe/internal/store"
)

// Server wires the WebAuthn ceremonies and session issuance to HTTP.
type Server struct {
	Registrar     *ceremony.Registrar
	Authenticator *ceremony.Authenticator
	Store         *store.Store
	Sessions      *session.Signer
	RPID          string
	RPName        string
	Log           *slog.Logger
}

// Routes returns the server's handler: the four ceremony endpoints plus
// the demo page.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register/begin", s.handleRegisterBegin)
	mux.HandleFunc("POST /register/finish", s.handleRegisterFinish)
	mux.HandleFunc("POST /login/begin", s.handleLoginBegin)
	mux.HandleFunc("POST /login/finish", s.handleLoginFinish)
	mux.HandleFunc("GET /demo", s.handleDemoPage)
	mux.HandleFunc("GET /credentials", s.handleListCredentials)
	mux.HandleFunc("DELETE /credentials/{id}", s.handleDeleteCredential)
	return mux
}

// authenticate extracts and verifies a bearer session token, returning
// its claims. Used only by the credential-management endpoints — the
// four ceremony endpoints above need no prior session, that's the point.
func (s *Server) authenticate(r *http.Request) (session.Claims, error) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return session.Claims{}, session.ErrMalformedToken
	}
	return s.Sessions.Verify(strings.TrimPrefix(h, prefix))
}

type registerBeginRequest struct {
	Username string `json:"username"`
}

type publicKeyCredentialParam struct {
	Type string `json:"type"`
	Alg  int64  `json:"alg"`
}

type relyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type userEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type authenticatorSelection struct {
	ResidentKey        string `json:"residentKey"`
	RequireResidentKey bool   `json:"requireResidentKey"`
	UserVerification   string `json:"userVerification"`
}

type creationOptions struct {
	RP                     relyingParty               `json:"rp"`
	User                   userEntity                 `json:"user"`
	Challenge              string                     `json:"challenge"`
	PubKeyCredParams       []publicKeyCredentialParam `json:"pubKeyCredParams"`
	Timeout                int64                      `json:"timeout"`
	Attestation            string                     `json:"attestation"`
	AuthenticatorSelection authenticatorSelection     `json:"authenticatorSelection"`
}

func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var req registerBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	challenge, err := s.Registrar.Challenges.Issue(req.Username, ceremony.PurposeRegister)
	if err != nil {
		s.logErr("register/begin", err)
		writeError(w, http.StatusInternalServerError, "could not start registration")
		return
	}
	userID := make([]byte, 16)
	if _, err := rand.Read(userID); err != nil {
		s.logErr("register/begin", err)
		writeError(w, http.StatusInternalServerError, "could not start registration")
		return
	}

	writeJSON(w, http.StatusOK, creationOptions{
		RP:        relyingParty{ID: s.RPID, Name: s.RPName},
		User:      userEntity{ID: base64.RawURLEncoding.EncodeToString(userID), Name: req.Username, DisplayName: req.Username},
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		PubKeyCredParams: []publicKeyCredentialParam{
			{Type: "public-key", Alg: cose.AlgES256},
			{Type: "public-key", Alg: cose.AlgRS256},
			{Type: "public-key", Alg: cose.AlgEdDSA},
		},
		Timeout:     int64(ceremony.ChallengeTTL / time.Millisecond),
		Attestation: "none",
		// residentKey required: the demo's "Log in (usernameless)" path
		// needs a discoverable credential, and browsers default to
		// non-resident when this is left unset (verified against real
		// Chromium: registration succeeds either way, but a subsequent
		// discoverable login finds nothing and times out).
		AuthenticatorSelection: authenticatorSelection{
			ResidentKey:        "required",
			RequireResidentKey: true,
			UserVerification:   string(s.Registrar.UVPolicy),
		},
	})
}

type registerFinishRequest struct {
	Username          string `json:"username"`
	RawID             string `json:"rawId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AttestationObject string `json:"attestationObject"`

	// Nickname is an optional, display-only label for this credential
	// ("Touch ID on MacBook"). UV, if set, can only tighten the server's
	// configured UV policy for this one registration, never loosen it
	// (policy.EffectivePolicy).
	Nickname string `json:"nickname"`
	UV       string `json:"uv"`
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var req registerFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	credID, err1 := base64.RawURLEncoding.DecodeString(req.RawID)
	clientDataJSON, err2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	attestationObject, err3 := base64.RawURLEncoding.DecodeString(req.AttestationObject)
	if err1 != nil || err2 != nil || err3 != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := s.Registrar.Register(ceremony.RegistrationRequest{
		Username:          req.Username,
		CredentialID:      credID,
		ClientDataJSON:    clientDataJSON,
		AttestationObject: attestationObject,
		Nickname:          req.Nickname,
		UVOverride:        policy.UVPolicy(req.UV),
	}); err != nil {
		s.logErr("register/finish", err)
		writeError(w, http.StatusBadRequest, "registration failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type loginBeginRequest struct {
	Username string `json:"username"`
}

type allowedCredential struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type requestOptions struct {
	RPID             string              `json:"rpId"`
	Challenge        string              `json:"challenge"`
	Timeout          int64               `json:"timeout"`
	UserVerification string              `json:"userVerification"`
	AllowCredentials []allowedCredential `json:"allowCredentials,omitempty"`

	// FlowID is set only for a discoverable/usernameless begin (empty
	// username) — an opaque token the client must echo back at
	// /login/finish so the server can locate the pending challenge. It
	// is not part of the WebAuthn PublicKeyCredentialRequestOptions
	// shape; it is vouchsafe's own bookkeeping field, and plays no part
	// in deciding who the ceremony authenticates as (see AssertionRequest
	// in internal/ceremony — that's resolved from the credential, W8).
	FlowID string `json:"flowId,omitempty"`
}

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req loginBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	// The username (or, for a discoverable/usernameless flow, a random
	// flow ID) only ever routes to the pending challenge below — see
	// AssertionRequest.Username's doc comment in internal/ceremony.
	challengeKey := req.Username
	var allow []allowedCredential
	if req.Username == "" {
		flowID, err := randomFlowID()
		if err != nil {
			s.logErr("login/begin", err)
			writeError(w, http.StatusInternalServerError, "could not start login")
			return
		}
		challengeKey = flowID
	} else {
		creds, err := s.Store.FindByUsername(req.Username)
		if err != nil {
			s.logErr("login/begin", err)
			writeError(w, http.StatusInternalServerError, "could not start login")
			return
		}
		for _, c := range creds {
			allow = append(allow, allowedCredential{Type: "public-key", ID: base64.RawURLEncoding.EncodeToString(c.ID)})
		}
	}

	challenge, err := s.Authenticator.Challenges.Issue(challengeKey, ceremony.PurposeLogin)
	if err != nil {
		s.logErr("login/begin", err)
		writeError(w, http.StatusInternalServerError, "could not start login")
		return
	}

	resp := requestOptions{
		RPID:             s.RPID,
		Challenge:        base64.RawURLEncoding.EncodeToString(challenge),
		Timeout:          int64(ceremony.ChallengeTTL / time.Millisecond),
		UserVerification: string(s.Authenticator.UVPolicy),
		AllowCredentials: allow,
	}
	if req.Username == "" {
		resp.FlowID = challengeKey
	}
	writeJSON(w, http.StatusOK, resp)
}

func randomFlowID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type loginFinishRequest struct {
	Username string `json:"username"`
	// FlowID is required instead of Username when completing a
	// discoverable/usernameless login (see requestOptions.FlowID).
	FlowID            string `json:"flowId"`
	RawID             string `json:"rawId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`

	// UV, if set, can only tighten the server's configured UV policy for
	// this one login, never loosen it (policy.EffectivePolicy).
	UV string `json:"uv"`
}

type loginFinishResponse struct {
	Token string `json:"token"`
	User  string `json:"user"`
	UV    bool   `json:"uv"`
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req loginFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	credID, err1 := base64.RawURLEncoding.DecodeString(req.RawID)
	clientDataJSON, err2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	authData, err3 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	sig, err4 := base64.RawURLEncoding.DecodeString(req.Signature)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	challengeKey := req.Username
	if challengeKey == "" {
		challengeKey = req.FlowID
	}

	result, err := s.Authenticator.Login(ceremony.AssertionRequest{
		Username:          challengeKey,
		CredentialID:      credID,
		ClientDataJSON:    clientDataJSON,
		AuthenticatorData: authData,
		Signature:         sig,
		UVOverride:        policy.UVPolicy(req.UV),
	})
	if err != nil {
		s.logErr("login/finish", err)
		writeError(w, http.StatusUnauthorized, "login failed")
		return
	}

	token, err := s.Sessions.Issue(result.Username, result.UVPerformed)
	if err != nil {
		s.logErr("login/finish", err)
		writeError(w, http.StatusInternalServerError, "could not issue session")
		return
	}
	writeJSON(w, http.StatusOK, loginFinishResponse{Token: token, User: result.Username, UV: result.UVPerformed})
}

type credentialSummary struct {
	ID        string    `json:"id"`
	Algorithm int64     `json:"algorithm"`
	CreatedAt time.Time `json:"createdAt"`
	AAGUID    string    `json:"aaguid"`
	Nickname  string    `json:"nickname,omitempty"`
}

// handleListCredentials returns the caller's own credentials — resolved
// from their session token, never from a query parameter, so one user
// can't list another's by asking.
func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	claims, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	creds, err := s.Store.FindByUsername(claims.Username)
	if err != nil {
		s.logErr("credentials/list", err)
		writeError(w, http.StatusInternalServerError, "could not list credentials")
		return
	}
	out := make([]credentialSummary, 0, len(creds))
	for _, c := range creds {
		out = append(out, credentialSummary{
			ID:        base64.RawURLEncoding.EncodeToString(c.ID),
			Algorithm: c.Algorithm,
			CreatedAt: c.CreatedAt,
			AAGUID:    base64.RawURLEncoding.EncodeToString(c.AAGUID),
			Nickname:  c.Nickname,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeleteCredential revokes one of the caller's own credentials.
// Ownership is checked before deleting; a credential that doesn't exist
// and one that exists but belongs to someone else get the identical 404
// — the difference isn't something a non-owner should be able to probe.
func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	claims, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	credID, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid credential id")
		return
	}
	cred, ok, err := s.Store.FindByID(credID)
	if err != nil {
		s.logErr("credentials/delete", err)
		writeError(w, http.StatusInternalServerError, "could not delete credential")
		return
	}
	if !ok || cred.Username != claims.Username {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	if err := s.Store.DeleteCredential(credID); err != nil {
		s.logErr("credentials/delete", err)
		writeError(w, http.StatusInternalServerError, "could not delete credential")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func (s *Server) logErr(op string, err error) {
	if s.Log != nil {
		s.Log.Error(op, "error", err)
	}
}
