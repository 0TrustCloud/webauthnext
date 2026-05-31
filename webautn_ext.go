package webauthnext

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm/legacy/tpm2"
	"gopkg.in/square/go-jose.v2"

	"github.com/0TrustCloud/guikit"
	"github.com/0TrustCloud/secure_policy"
	"github.com/0TrustCloud/ultimate_db"
)

const AuthPageID ultimate_db.PageID = 1

type PasskeyUser struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	DisplayName string                `json:"displayName"`
	Credentials []webauthn.Credential `json:"credentials"`
}

func (u *PasskeyUser) WebAuthnID() []byte { return u.ID }
func (u *PasskeyUser) WebAuthnName() string { return u.Name }
func (u *PasskeyUser) WebAuthnDisplayName() string { return u.DisplayName }
func (u *PasskeyUser) WebAuthnIcon() string { return "" }
func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type OIDCClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

type AuthRequest struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	Scope               string `json:"scope"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type ActiveSession struct {
	Username   string `json:"username"`
	DBSCPubKey string `json:"dbsc_pub_key,omitempty"` 
}

type Provider struct {
	gk             *guikit.GUIKit
	wa             *webauthn.WebAuthn
	issuer         string
	signingKey     *rsa.PrivateKey
	keyID          string
	SessionManager *secure_policy.SessionManager

	OnLoginSuccess func(username string, w http.ResponseWriter, r *http.Request)
}

func New(gk *guikit.GUIKit, sm *secure_policy.SessionManager, rpDisplayName, rpID, rpOrigin string) (*Provider, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn instance: %w", err)
	}

	// --------------------------------------------------
	// PERSISTENT OIDC ISSUER KEY
	// --------------------------------------------------
	var privKey *rsa.PrivateKey
	txn := gk.DB.BeginTxn()
	keyBytes, err := gk.DB.Read(AuthPageID, txn, []byte("oidc_master_key"))
	gk.DB.CommitTxn(txn)

	if err == nil && len(keyBytes) > 0 {
		privKey, _ = x509.ParsePKCS1PrivateKey(keyBytes)
	}

	if privKey == nil {
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate signing key: %w", err)
		}
		wTxn := gk.DB.BeginTxn()
		gk.DB.Write(AuthPageID, wTxn, []byte("oidc_master_key"), x509.MarshalPKCS1PrivateKey(privKey), 0)
		gk.DB.CommitTxn(wTxn)
	}

	p := &Provider{
		gk:             gk,
		wa:             wa,
		issuer:         rpOrigin,
		signingKey:     privKey,
		keyID:          "v1-default",
		SessionManager: sm,
	}

	gk.Mux.HandleFunc("GET /auth/register/begin", p.BeginRegistration)
	gk.Mux.HandleFunc("POST /auth/register/finish", p.FinishRegistration)
	gk.Mux.HandleFunc("GET /auth/login/begin", p.BeginLogin)
	gk.Mux.HandleFunc("POST /auth/login/finish", p.FinishLogin)
	gk.Mux.HandleFunc("GET /auth/webauthn.js", p.ServeJS)

	gk.Mux.HandleFunc("POST /auth/dbsc/register", p.DBSCRegister)
	gk.Mux.HandleFunc("POST /auth/dbsc/refresh", p.DBSCRefresh)

	gk.Mux.HandleFunc("GET /.well-known/openid-configuration", p.ServeDiscovery)
	gk.Mux.HandleFunc("GET /auth/keys", p.ServeJWKS)
	gk.Mux.HandleFunc("GET /auth/authorize", p.Authorize)
	gk.Mux.HandleFunc("POST /auth/token", p.TokenExchange)

	gk.Mux.HandleFunc("POST /auth/revoke", p.RevokeToken)
	gk.Mux.HandleFunc("POST /auth/clients/register", p.AuthGuard(p.RegisterClient))

	return p, nil
}

func (p *Provider) AuthGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		subjectID, err := p.SessionManager.ValidateCookieToken(cookie.Value)
		if err != nil {
			http.Error(w, "Session expired or revoked", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "username", subjectID)
		next(w, r.WithContext(ctx))
	}
}

func (p *Provider) extractJTIFromCookie(cookieValue string) (string, error) {
	if strings.HasPrefix(cookieValue, "user_session_") {
		cookieValue = strings.TrimPrefix(cookieValue, "user_session_")
	}
	token, _, err := new(jwt.Parser).ParseUnverified(cookieValue, jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["jti"] == nil {
		return "", errors.New("malformed claims")
	}
	return claims["jti"].(string), nil
}

func (p *Provider) DBSCRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JWT string `json:"jwt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid DBSC registration payload", http.StatusBadRequest)
		return
	}

	token, _, err := new(jwt.Parser).ParseUnverified(req.JWT, jwt.MapClaims{})
	if err != nil {
		http.Error(w, "Invalid JWT format", http.StatusBadRequest)
		return
	}

	jwkBytes, err := json.Marshal(token.Header["jwk"])
	if err != nil {
		http.Error(w, "Missing JWK in registration", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "No active session to bind", http.StatusUnauthorized)
		return
	}

	jti, err := p.extractJTIFromCookie(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid session token format", http.StatusUnauthorized)
		return
	}

	txn := p.gk.DB.BeginTxn()
	sessionBytes, err := p.gk.DB.Read(AuthPageID, txn, []byte("session:"+jti))
	p.gk.DB.CommitTxn(txn)

	if err == nil && len(sessionBytes) > 0 {
		var session ActiveSession
		json.Unmarshal(sessionBytes, &session)

		session.DBSCPubKey = string(jwkBytes)
		updatedBytes, _ := json.Marshal(session)

		wTxn := p.gk.DB.BeginTxn()
		p.gk.DB.Write(AuthPageID, wTxn, []byte("session:"+jti), updatedBytes, 24*time.Hour)
		p.gk.DB.CommitTxn(wTxn)
	}

	w.WriteHeader(http.StatusOK)
}

func (p *Provider) DBSCRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Session missing", http.StatusUnauthorized)
		return
	}

	jti, err := p.extractJTIFromCookie(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid session token format", http.StatusUnauthorized)
		return
	}

	txn := p.gk.DB.BeginTxn()
	sessionBytes, err := p.gk.DB.Read(AuthPageID, txn, []byte("session:"+jti))
	p.gk.DB.CommitTxn(txn)

	if err != nil || len(sessionBytes) == 0 {
		http.Error(w, "Session expired completely", http.StatusUnauthorized)
		return
	}

	var session ActiveSession
	json.Unmarshal(sessionBytes, &session)

	if session.DBSCPubKey == "" {
		http.Error(w, "Session is not bound to hardware", http.StatusBadRequest)
		return
	}

	responseHeader := r.Header.Get("Sec-Session-Response")
	if responseHeader == "" {
		nonceBytes := make([]byte, 32)
		rand.Read(nonceBytes)
		nonce := base64.URLEncoding.EncodeToString(nonceBytes)

		nTxn := p.gk.DB.BeginTxn()
		p.gk.DB.Write(AuthPageID, nTxn, []byte("dbsc_nonce:"+nonce), []byte(session.Username), 2*time.Minute)
		p.gk.DB.CommitTxn(nTxn)

		w.Header().Set("Sec-Session-Challenge", fmt.Sprintf(`"%s"`, nonce))
		http.Error(w, "Challenge required", http.StatusUnauthorized)
		return
	}

	token, _ := jwt.Parse(responseHeader, func(token *jwt.Token) (interface{}, error) {
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON([]byte(session.DBSCPubKey)); err != nil {
			return nil, err
		}
		return jwk.Key, nil
	})

	if token != nil && token.Valid {
		cookie.MaxAge = 86400
		cookieStr := cookie.String() + "; Sec-Provided-Session-Key"
		w.Header().Add("Set-Cookie", cookieStr)
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Invalid DBSC response", http.StatusForbidden)
}

func (p *Provider) SignPayload(payload []byte) []byte {
	hash := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.signingKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil
	}
	return signature
}

func (p *Provider) RegisterServiceIdentity(name string, tpmPublicBytes []byte) error {
	_, err := tpm2.DecodePublic(tpmPublicBytes)
	if err != nil {
		return fmt.Errorf("failed to decode TPM2B_PUBLIC structure: %w", err)
	}

	user := &PasskeyUser{
		ID:          tpmPublicBytes,
		Name:        name,
		DisplayName: "Service: " + name,
	}

	return p.saveUser(user)
}

func (p *Provider) VerifyAddressClaim(remoteID []byte, address string, dbscProof []byte) (bool, error) {
	if len(dbscProof) == 0 {
		return false, errors.New("connection rejected: missing DBSC hardware proof")
	}

	proof := string(dbscProof)
	parts := strings.SplitN(proof, ":", 3)
	if len(parts) != 3 {
		return false, errors.New("connection rejected: malformed DBSC proof")
	}
	serviceName, nonce, sigBase64 := parts[0], parts[1], parts[2]

	user, err := p.getUser(serviceName)
	if err != nil {
		return false, errors.New("service identity not found")
	}

	tpmPubKey, err := tpm2.DecodePublic(user.ID)
	if err != nil {
		return false, errors.New("failed to parse stored TPM key")
	}

	cryptoKey, err := tpmPubKey.Key()
	if err != nil {
		return false, errors.New("failed to extract cryptographic key")
	}

	signature, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return false, errors.New("invalid signature encoding")
	}

	payload := fmt.Sprintf("%s|%s", nonce, address)
	payloadHash := sha256.Sum256([]byte(payload))

	rsaPubKey, ok := cryptoKey.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("unsupported TPM key type (expected RSA)")
	}

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, payloadHash[:], signature)
	if err != nil {
		return false, errors.New("hardware signature verification failed")
	}

	var timestamp int64
	fmt.Sscanf(nonce, "%d", &timestamp)
	if time.Now().Unix()-timestamp > 60 {
		return false, errors.New("DBSC Proof expired")
	}

	return true, nil
}

func (p *Provider) getUser(username string) (*PasskeyUser, error) {
	txn := p.gk.DB.BeginTxn()
	val, err := p.gk.DB.Read(AuthPageID, txn, []byte("user:"+username))
	p.gk.DB.CommitTxn(txn)

	if err != nil {
		return nil, err
	}
	var user PasskeyUser
	if err := json.Unmarshal(val, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *Provider) saveUser(user *PasskeyUser) error {
	val, _ := json.Marshal(user)
	txn := p.gk.DB.BeginTxn()
	err := p.gk.DB.Write(AuthPageID, txn, []byte("user:"+user.Name), val, 0)
	p.gk.DB.CommitTxn(txn)
	return err
}

func (p *Provider) saveSession(sessionKey string, sessionData webauthn.SessionData) error {
	val, _ := json.Marshal(sessionData)
	txn := p.gk.DB.BeginTxn()
	err := p.gk.DB.Write(AuthPageID, txn, []byte("session:"+sessionKey), val, 5*time.Minute)
	p.gk.DB.CommitTxn(txn)
	return err
}

func (p *Provider) getSession(sessionKey string) (webauthn.SessionData, error) {
	txn := p.gk.DB.BeginTxn()
	val, err := p.gk.DB.Read(AuthPageID, txn, []byte("session:"+sessionKey))
	p.gk.DB.CommitTxn(txn)

	var sessionData webauthn.SessionData
	if err != nil {
		return sessionData, err
	}
	err = json.Unmarshal(val, &sessionData)
	return sessionData, err
}

func (p *Provider) getClient(clientID string) (*OIDCClient, error) {
	txn := p.gk.DB.BeginTxn()
	val, err := p.gk.DB.Read(AuthPageID, txn, []byte("client:"+clientID))
	p.gk.DB.CommitTxn(txn)

	if err != nil {
		return nil, err
	}
	var client OIDCClient
	if err := json.Unmarshal(val, &client); err != nil {
		return nil, err
	}
	return &client, nil
}

func (p *Provider) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Must supply username", http.StatusBadRequest)
		return
	}

	if _, err := p.getUser(username); err == nil {
		http.Error(w, "Username already taken", http.StatusConflict)
		return
	}

	user := &PasskeyUser{ID: []byte(username), Name: username, DisplayName: username}
	if err := p.saveUser(user); err != nil {
		http.Error(w, "Database error saving user", http.StatusInternalServerError)
		return
	}

	options, sessionData, err := p.wa.BeginRegistration(user)
	if err != nil {
		http.Error(w, "WebAuthn error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := p.saveSession("reg_"+username, *sessionData); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (p *Provider) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	user, err := p.getUser(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	sessionData, err := p.getSession("reg_" + username)
	if err != nil {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	credential, err := p.wa.FinishRegistration(user, sessionData, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user.Credentials = append(user.Credentials, *credential)
	p.saveUser(user)
	p.handlePostAuth(username, w, r)
}

func (p *Provider) BeginLogin(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	user, err := p.getUser(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	options, sessionData, err := p.wa.BeginLogin(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := p.saveSession("login_"+username, *sessionData); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (p *Provider) FinishLogin(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	user, err := p.getUser(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	sessionData, err := p.getSession("login_" + username)
	if err != nil {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	credential, err := p.wa.FinishLogin(user, sessionData, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for i, c := range user.Credentials {
		if bytes.Equal(c.ID, credential.ID) {
			user.Credentials[i].Authenticator.SignCount = credential.Authenticator.SignCount
			break
		}
	}
	p.saveUser(user)
	p.handlePostAuth(username, w, r)
}

func (p *Provider) handlePostAuth(username string, w http.ResponseWriter, r *http.Request) {
	if p.OnLoginSuccess != nil {
		p.OnLoginSuccess(username, w, r)
	}

	// FIX: Clean the string before it ever touches token generation
	cleanUsername := strings.TrimSpace(username)
	if strings.HasPrefix(cleanUsername, "user_session_") {
		cleanUsername = strings.TrimPrefix(cleanUsername, "user_session_")
	}

	tokenString, jti, err := p.SessionManager.IssueCookieToken([]byte(cleanUsername), 24*time.Hour)
	if err != nil {
		http.Error(w, "Failed to issue secure session", http.StatusInternalServerError)
		return
	}

	sessionCookie := &http.Cookie{
		Name:     "session_id",
		Value:    "user_session_" + tokenString,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	}

	cookieString := sessionCookie.String() + "; Sec-Provided-Session-Key"
	w.Header().Add("Set-Cookie", cookieString)

	nonceBytes := make([]byte, 32)
	rand.Read(nonceBytes)
	regChallenge := base64.URLEncoding.EncodeToString(nonceBytes)

	// FIX: Explicitly binds parameters using correct DBSC token semi-colon serialization without parentheses
	registrationHeader := fmt.Sprintf(`"/auth/dbsc/register"; challenge="%s"; es256`, regChallenge)
	w.Header().Set("Sec-Session-Registration", registrationHeader)

	sessionData := ActiveSession{
		Username: cleanUsername,
	}
	sessionBytes, _ := json.Marshal(sessionData)

	sTxn := p.gk.DB.BeginTxn()
	p.gk.DB.Write(AuthPageID, sTxn, []byte("session:"+jti), sessionBytes, 24*time.Hour)
	p.gk.DB.CommitTxn(sTxn)

	oidcCookie, err := r.Cookie("oidc_flow_id")
	if err == nil && oidcCookie.Value != "" {
		flowID := oidcCookie.Value

		txn := p.gk.DB.BeginTxn()
		authReqBytes, err := p.gk.DB.Read(AuthPageID, txn, []byte("oidc_flow:"+flowID))
		p.gk.DB.CommitTxn(txn)

		if err == nil {
			var authReq AuthRequest
			if json.Unmarshal(authReqBytes, &authReq) == nil {
				authCode := "code_" + fmt.Sprintf("%d", time.Now().UnixNano())

				contextData, _ := json.Marshal(map[string]string{
					"username":              cleanUsername,
					"client_id":             authReq.ClientID,
					"redirect_uri":          authReq.RedirectURI,
					"nonce":                 authReq.Nonce,
					"scope":                 authReq.Scope,
					"code_challenge":        authReq.CodeChallenge,
					"code_challenge_method": authReq.CodeChallengeMethod,
				})

				wTxn := p.gk.DB.BeginTxn()
				p.gk.DB.Write(AuthPageID, wTxn, []byte("auth_code:"+authCode), contextData, 5*time.Minute)
				p.gk.DB.CommitTxn(wTxn)

				http.SetCookie(w, &http.Cookie{Name: "oidc_flow_id", Value: "", Path: "/", MaxAge: -1})

				redirectURL := fmt.Sprintf("%s?code=%s&state=%s", authReq.RedirectURI, authCode, authReq.State)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"redirect_to": redirectURL})
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (p *Provider) ServeDiscovery(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + "/auth/authorize",
		"token_endpoint":                        p.issuer + "/auth/token",
		"revocation_endpoint":                   p.issuer + "/auth/revoke",
		"jwks_uri":                              p.issuer + "/auth/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (p *Provider) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       &p.signingKey.PublicKey,
		KeyID:     p.keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

func (p *Provider) Authorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	scope := r.URL.Query().Get("scope")
	responseType := r.URL.Query().Get("response_type")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	client, err := p.getClient(clientID)
	if err != nil || responseType != "code" {
		http.Error(w, "Unauthorized client or unsupported response type", http.StatusBadRequest)
		return
	}

	validURI := false
	for _, u := range client.RedirectURIs {
		if u == redirectURI {
			validURI = true
			break
		}
	}
	if !validURI {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	sessionCookie, err := r.Cookie("session_id")
	if err == nil {
		subjectID, validationErr := p.SessionManager.ValidateCookieToken(sessionCookie.Value)
		if validationErr == nil {
			txn := p.gk.DB.BeginTxn()
			mfaVerified, _ := p.gk.DB.Read(AuthPageID, txn, []byte("mfa_verified_"+subjectID))
			p.gk.DB.CommitTxn(txn)

			if string(mfaVerified) != "true" {
				http.Redirect(w, r, "/mfa/verify?target="+r.URL.String(), http.StatusFound)
				return
			}
		}
	}

	flowID := "flow_" + fmt.Sprintf("%d", time.Now().UnixNano())

	authReq := AuthRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Nonce:               nonce,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
	authReqBytes, _ := json.Marshal(authReq)

	wTxn := p.gk.DB.BeginTxn()
	p.gk.DB.Write(AuthPageID, wTxn, []byte("oidc_flow:"+flowID), authReqBytes, 10*time.Minute)
	p.gk.DB.CommitTxn(wTxn)

	http.SetCookie(w, &http.Cookie{Name: "oidc_flow_id", Value: flowID, Path: "/", Secure: true, HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (p *Provider) TokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")

	_, err := p.getClient(clientID)
	if err != nil {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	contextKey := []byte("auth_code:" + code)
	txn := p.gk.DB.BeginTxn()
	contextBytes, err := p.gk.DB.Read(AuthPageID, txn, contextKey)
	p.gk.DB.CommitTxn(txn)

	if err != nil {
		http.Error(w, "Invalid authorization code", http.StatusBadRequest)
		return
	}

	wTxn := p.gk.DB.BeginTxn()
	p.gk.DB.Write(AuthPageID, wTxn, contextKey, nil, -1)
	p.gk.DB.CommitTxn(wTxn)

	var context map[string]string
	json.Unmarshal(contextBytes, &context)

	if context["client_id"] != clientID {
		http.Error(w, "Client mismatch", http.StatusBadRequest)
		return
	}

	storedChallenge := context["code_challenge"]
	if storedChallenge != "" {
		codeVerifier := r.FormValue("code_verifier")
		if codeVerifier == "" {
			http.Error(w, "Missing code_verifier for PKCE", http.StatusBadRequest)
			return
		}

		challengeMethod := context["code_challenge_method"]
		if challengeMethod == "S256" {
			hash := sha256.Sum256([]byte(codeVerifier))
			expectedChallenge := strings.TrimRight(base64.URLEncoding.EncodeToString(hash[:]), "=")

			if expectedChallenge != storedChallenge {
				http.Error(w, "Invalid code_verifier", http.StatusBadRequest)
				return
			}
		} else {
			if codeVerifier != storedChallenge {
				http.Error(w, "Invalid code_verifier", http.StatusBadRequest)
				return
			}
		}
	}

	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	accessToken := hex.EncodeToString(tokenBytes)

	aTxn := p.gk.DB.BeginTxn()
	p.gk.DB.Write(AuthPageID, aTxn, []byte("token:"+accessToken), []byte(context["username"]), 1*time.Hour)
	p.gk.DB.CommitTxn(aTxn)

	now := time.Now()
	idClaims := jwt.MapClaims{
		"iss":                p.issuer,
		"sub":                context["username"],
		"aud":                clientID,
		"exp":                now.Add(1 * time.Hour).Unix(),
		"iat":                now.Unix(),
		"nonce":              context["nonce"],
		"preferred_username": context["username"],
		"scopes":             strings.Split(context["scope"], " "),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
	token.Header["kid"] = p.keyID
	idTokenString, err := token.SignedString(p.signingKey)
	if err != nil {
		http.Error(w, "Token production error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idTokenString,
		"scope":        context["scope"],
	})
}

func (p *Provider) RevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "missing token parameter", http.StatusBadRequest)
		return
	}

	txn := p.gk.DB.BeginTxn()
	p.gk.DB.Write(AuthPageID, txn, []byte("token:"+token), nil, -1)
	p.gk.DB.CommitTxn(txn)

	w.WriteHeader(http.StatusOK)
}

func (p *Provider) RegisterClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	idBytes := make([]byte, 16)
	secretBytes := make([]byte, 32)
	rand.Read(idBytes)
	rand.Read(secretBytes)

	client := OIDCClient{
		ClientID:     hex.EncodeToString(idBytes),
		ClientSecret: hex.EncodeToString(secretBytes),
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
	}

	clientBytes, _ := json.Marshal(client)
	txn := p.gk.DB.BeginTxn()
	p.gk.DB.Write(AuthPageID, txn, []byte("client:"+client.ClientID), clientBytes, 0)
	p.gk.DB.CommitTxn(txn)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(client)
}

func (p *Provider) ServeJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(`
async function passkeyRegister(username) {
    try {
        if (!username) throw new Error("Please enter a username");
        const resp = await fetch('/auth/register/begin?username=' + encodeURIComponent(username));
        if (!resp.ok) throw new Error("Server error: " + await resp.text());
        const opts = await resp.json();
        opts.publicKey.challenge = base64urlToBuffer(opts.publicKey.challenge);
        opts.publicKey.user.id = base64urlToBuffer(opts.publicKey.user.id);
        if(opts.publicKey.excludeCredentials) { opts.publicKey.excludeCredentials.forEach(c => c.id = base64urlToBuffer(c.id)); }
        const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
        const finishResp = await fetch('/auth/register/finish?username=' + encodeURIComponent(username), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: cred.id, rawId: bufferToBase64url(cred.rawId), type: cred.type, response: { attestationObject: bufferToBase64url(cred.response.attestationObject), clientDataJSON: bufferToBase64url(cred.response.clientDataJSON), }, }),
        });
        if (!finishResp.ok) throw new Error("Server rejected registration: " + await finishResp.text());
        
        const resData = await finishResp.json();
        if (resData.redirect_to) { window.location.href = resData.redirect_to; } 
        else { window.location.href = "/"; }
    } catch (err) { console.error(err); alert("Registration Failed: " + err.message); }
}

async function passkeyLogin(username) {
    try {
        if (!username) throw new Error("Please enter a username");
        const resp = await fetch('/auth/login/begin?username=' + encodeURIComponent(username));
        if (!resp.ok) throw new Error("Server error: " + await resp.text());
        const opts = await resp.json();
        opts.publicKey.challenge = base64urlToBuffer(opts.publicKey.challenge);
        if (opts.publicKey.allowCredentials) { opts.publicKey.allowCredentials.forEach(c => c.id = base64urlToBuffer(c.id)); }
        const assertion = await navigator.credentials.get({ publicKey: opts.publicKey });
        const finishResp = await fetch('/auth/login/finish?username=' + encodeURIComponent(username), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: assertion.id, rawId: bufferToBase64url(assertion.rawId), type: assertion.type, response: { authenticatorData: bufferToBase64url(assertion.response.authenticatorData), clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON), signature: bufferToBase64url(assertion.response.signature), userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null, }, }),
        });
        if (!finishResp.ok) throw new Error("Server rejected login: " + await finishResp.text());
        
        const resData = await finishResp.json();
        if (resData.redirect_to) { window.location.href = resData.redirect_to; } 
        else { window.location.href = "/"; }
    } catch (err) { console.error(err); alert("Login Failed: " + err.message); }
}

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const charCode of bytes) { str += String.fromCharCode(charCode); }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function base64urlToBuffer(base64url) {
    const padding = '=='.slice(0, (4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const str = atob(base64);
    const buffer = new ArrayBuffer(str.length);
    const byteView = new Uint8Array(buffer);
    for (let i = 0; i < str.length; i++) { byteView[i] = str.charCodeAt(i); }
    return buffer;
}
`))
}
