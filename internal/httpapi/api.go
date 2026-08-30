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
	"time"

	"github.com/jay-opensource/Vouchsafe/internal/ceremony"
	"github.com/jay-opensource/Vouchsafe/internal/cose"
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
	return mux
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

type creationOptions struct {
	RP               relyingParty               `json:"rp"`
	User             userEntity                 `json:"user"`
	Challenge        string                     `json:"challenge"`
	PubKeyCredParams []publicKeyCredentialParam `json:"pubKeyCredParams"`
	Timeout          int64                      `json:"timeout"`
	Attestation      string                     `json:"attestation"`
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
		},
		Timeout:     int64(ceremony.ChallengeTTL / time.Millisecond),
		Attestation: "none",
	})
}

type registerFinishRequest struct {
	Username          string `json:"username"`
	RawID             string `json:"rawId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AttestationObject string `json:"attestationObject"`
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
	AllowCredentials []allowedCredential `json:"allowCredentials"`
}

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req loginBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	creds, err := s.Store.FindByUsername(req.Username)
	if err != nil {
		s.logErr("login/begin", err)
		writeError(w, http.StatusInternalServerError, "could not start login")
		return
	}
	challenge, err := s.Authenticator.Challenges.Issue(req.Username, ceremony.PurposeLogin)
	if err != nil {
		s.logErr("login/begin", err)
		writeError(w, http.StatusInternalServerError, "could not start login")
		return
	}

	allow := make([]allowedCredential, 0, len(creds))
	for _, c := range creds {
		allow = append(allow, allowedCredential{Type: "public-key", ID: base64.RawURLEncoding.EncodeToString(c.ID)})
	}
	writeJSON(w, http.StatusOK, requestOptions{
		RPID:             s.RPID,
		Challenge:        base64.RawURLEncoding.EncodeToString(challenge),
		Timeout:          int64(ceremony.ChallengeTTL / time.Millisecond),
		UserVerification: string(s.Authenticator.UVPolicy),
		AllowCredentials: allow,
	})
}

type loginFinishRequest struct {
	Username          string `json:"username"`
	RawID             string `json:"rawId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
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

	result, err := s.Authenticator.Login(ceremony.AssertionRequest{
		Username:          req.Username,
		CredentialID:      credID,
		ClientDataJSON:    clientDataJSON,
		AuthenticatorData: authData,
		Signature:         sig,
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
