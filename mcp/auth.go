package mcp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/mcpbus-io/mcpbus/storages/auth"
	"github.com/mcpbus-io/mcpbus/utils"
)

const (
	smpEndpoint = "/.well-known/oauth-authorization-server"

	oauthRegisterEndpoint             = "/oauth/register"
	oauthAuthorizeEndpoint            = "/oauth/authorize"
	oauthTokenEndpoint                = "/oauth/token"
	oauthIntegrationAuthorizeEndpoint = "/oauth/integrations/authorize"
)

func (s *StreamableServer) smpHandler(w http.ResponseWriter, r *http.Request) {
	s.addCommonHeaders(w)

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if mcpProtoVersion := r.Header.Get(mcpProtocolVersionHeader); mcpProtoVersion != mcpVersion {
		log.WithField(mcpProtocolVersionHeader, mcpProtoVersion).Error("Invalid protocol version")
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}

	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(http.StatusOK)
	responseJson, _ := json.Marshal(s.metaData)
	if _, err := fmt.Fprintln(w, string(responseJson)); err != nil {
		log.WithError(err).Error("Failed to write meta data document response")
	}
}

func (s *StreamableServer) oauthRegisterHandler(w http.ResponseWriter, r *http.Request) {
	s.addCommonHeaders(w)

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Content-Type") != jsonContentType {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.WithError(err).Error("Failed to read register body")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	registerRequest := auth.ClientMetadata{}
	if err := json.Unmarshal(body, &registerRequest); err != nil {
		log.WithError(err).Error("Failed to unmarshal register request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	registerResponse := &auth.RegisterResponse{
		ClientID:              utils.NewId(),
		ClientSecret:          utils.NewId(),
		ClientIDIssuedAt:      time.Now().Unix(),
		ClientSecretExpiresAt: time.Now().Add(time.Minute * 30).Unix(), // TODO: make it configurable
		ClientMetadata:        registerRequest,
	}

	responseJson, err := json.Marshal(registerResponse)
	if err != nil {
		log.WithError(err).Error("Failed to marshal register response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := s.authStorage.AddClient(registerResponse); err != nil {
		log.WithError(err).Error("Failed to store client")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", jsonContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)

	if _, err := fmt.Fprintln(w, string(responseJson)); err != nil {
		log.Errorf("Failed to write error response: %v", err)
	}
}

func (s *StreamableServer) oauthAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	s.addCommonHeaders(w)

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// example of URL incoming
	// http://localhost:8080/oauth/authorize?response_type=code&client_id=abc&code_challenge=TqtkahkobwNIjBZU2lkmVxxs5UsEip1FdZ8_EDl_avY&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%3A6274%2Foauth%2Fcallback%2Fdebug&scope=read+write+manage

	queryValues := r.URL.Query()

	clientID := queryValues.Get("client_id")
	codeChallenge := queryValues.Get("code_challenge")
	codeChallengeMethod := queryValues.Get("code_challenge_method")
	state := queryValues.Get("state")
	redirectURI := queryValues.Get("redirect_uri")
	scope := queryValues.Get("scope")
	responseType := queryValues.Get("response_type")

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		// Invalid URL error is shown directly to the user
		log.WithError(err).Error("Failed to parse redirect URI")
		s.writeOAuthError(w, "invalid_code_challenge_method", "The redirect_uri parameter is missing or invalid",
			http.StatusBadRequest)
		return
	}

	query := redirectURL.Query()

	isError := false
	if !slices.Contains(s.metaData.CodeChallengeMethodsSupported, codeChallengeMethod) {
		log.WithFields(log.Fields{"invalid_request": codeChallengeMethod}).Error("Invalid code_challenge_method")
		query.Set("error", "invalid_request")
		query.Set("error_description", "Invalid code_challenge_method")
		isError = true
	}

	client, err := s.authStorage.GetClient(clientID)
	if err != nil {
		log.WithError(err).Error("Failed to get client")
		query.Set("error", "invalid_client")
		query.Set("error_description", "Invalid client_id")
		isError = true
	}

	if !slices.Contains(s.metaData.ResponseTypesSupported, responseType) || responseType != "code" { // TODO: process other supported response types
		log.WithFields(log.Fields{"response_type": responseType}).Error("Invalid response_type")
		query.Set("error", "unsupported_response_type")
		query.Set("error_description", "Invalid response_type")
		isError = true
	}

	// check scope requested
	if scope != "" && !s.isScopeValid(s.metaData.ScopesSupported, scope) {
		log.WithFields(log.Fields{"scope": scope}).Error("Invalid scope")
		query.Set("error", "invalid_scope")
		query.Set("error_description", "Invalid scope")
		isError = true
	}

	if codeChallenge == "" {
		log.Error("Missing code_challenge")
		query.Set("error", "invalid_request")
		query.Set("error_description", "Missing code_challenge")
		isError = true
	}

	var oAuthFlow *auth.OauthFlow
	if !isError {
		oAuthFlow = &auth.OauthFlow{
			RegisteredClient:    client,
			RedirectURI:         redirectURI,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			State:               state,
			Scope:               scope,
			AuthCode:            utils.NewId(),
		}
		if err := s.authStorage.AddOAuthFlow(oAuthFlow); err != nil {
			log.WithError(err).Error("Failed to add oauth flow")
			query.Set("error", "server_error")
			query.Set("error_description", "Server error")
			isError = true
		} else {
			// all good, send in redirect a code
			query.Set("code", oAuthFlow.AuthCode)
			if state != "" {
				query.Set("state", state)
			}
			redirectURL.RawQuery = query.Encode()
		}
	}

	// issue MCPBus redirect to a client right away in case of error
	if isError {
		http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
		return
	}

	if s.integration != nil {
		integrationState := utils.NewId()
		integrationRedirectURL := s.integration.GetOAuthRedirectURL(integrationState)
		// integration supports OAuth so we need to chain a redirect to it
		if integrationRedirectURL != "" {
			// we need to save MCPBus redirect URL for later
			oAuthFlow.FinalRedirectURL = redirectURL // we will redirect to it in oauthIntegrationAuthHandler
			if err := s.authStorage.AddOAuthFlowByCode(integrationState, oAuthFlow); err != nil {
				// issue MCPBus redirect in case of error
				log.WithError(err).Error("Failed to add oauth flow by code")
				newQuery := url.Values{}
				newQuery.Set("error", "server_error")
				newQuery.Set("error_description", "Server error")
				redirectURL.RawQuery = newQuery.Encode()
				http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
				return
			}
			// redirect to integration OAuth consent endpoint
			http.Redirect(w, r, integrationRedirectURL, http.StatusTemporaryRedirect)
			return
		}
	}

	// no integration with OAuth
	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}

func (s *StreamableServer) oauthIntegrationAuthHandler(w http.ResponseWriter, r *http.Request) {
	s.addCommonHeaders(w)

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.integration == nil {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	queryValues := r.URL.Query()

	// pickup OAuth flow started earlier by the code we issued for integration redirect
	state := queryValues.Get("state")
	authFlow, err := s.authStorage.GetOAuthFlow(state)
	if err != nil {
		log.WithError(err).Error("Failed to get oauth flow by OAuth state")
		s.writeOAuthError(w, "invalid_state", "The state parameter is missing or invalid",
			http.StatusBadRequest)
		return
	}

	// check if user approved access to the integration
	if approveError := queryValues.Get("error"); approveError != "" {
		// we need to issue redirect with access denied as well
		log.WithField("error", approveError).Error("Integration returned error")
		newQuery := url.Values{}
		newQuery.Set("error", approveError)
		newQuery.Set("error_description", "Server error")
		authFlow.FinalRedirectURL.RawQuery = newQuery.Encode()
		http.Redirect(w, r, authFlow.FinalRedirectURL.String(), http.StatusTemporaryRedirect)
		return
	}

	// check if received a AUth code from integration
	code := queryValues.Get("code")
	if code == "" {
		log.Error("Integration did not return auth code for exchange")
		newQuery := url.Values{}
		newQuery.Set("error", "access_denied")
		newQuery.Set("error_description", "Third party integration auth failed")
		authFlow.FinalRedirectURL.RawQuery = newQuery.Encode()
		http.Redirect(w, r, authFlow.FinalRedirectURL.String(), http.StatusTemporaryRedirect)
		return
	}

	// finally, exchange code for the integration OAuth token
	integrationToken, err := s.integration.ExchangeOauthCode(code)
	if err != nil {
		log.WithError(err).Error("Failed to exchange oauth code with integration")
		newQuery := url.Values{}
		newQuery.Set("error", "access_denied")
		newQuery.Set("error_description", "Third party integration auth failed")
		authFlow.FinalRedirectURL.RawQuery = newQuery.Encode()
		http.Redirect(w, r, authFlow.FinalRedirectURL.String(), http.StatusTemporaryRedirect)
		return
	}

	// associate integration token with MCPBus auth flow
	authFlow.IntegrationToken = integrationToken
	if err := s.authStorage.UpdateOAuthFlow(authFlow); err != nil {
		log.WithError(err).Error("Failed to update oauth flow")
		newQuery := url.Values{}
		newQuery.Set("error", "server_error")
		newQuery.Set("error_description", "Server error")
		authFlow.FinalRedirectURL.RawQuery = newQuery.Encode()
		http.Redirect(w, r, authFlow.FinalRedirectURL.String(), http.StatusTemporaryRedirect)
		return
	}

	// issue redirect with no errors to continue MCPBus OAuth flow
	http.Redirect(w, r, authFlow.FinalRedirectURL.String(), http.StatusTemporaryRedirect)
}

func (s *StreamableServer) isScopeValid(allowed []string, requested string) bool {
	for _, v := range strings.Split(requested, " ") {
		if !slices.Contains(allowed, v) {
			return false
		}
	}
	return true
}

func (s *StreamableServer) oauthTokenHandler(w http.ResponseWriter, r *http.Request) {
	s.addCommonHeaders(w)
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		log.WithError(err).Error("Failed to parse form")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	clientID := r.Form.Get("client_id")
	grantType := r.Form.Get("grant_type")

	if clientID == "" {
		log.Error("Missing client_id in token request")
		s.writeOAuthError(w, "invalid_request", "Missing client_id", http.StatusBadRequest)
		return
	}

	// TODO: check if redirect URI is the same as used for code auth

	var authToken *auth.AuthToken
	switch grantType {
	case "authorization_code":
		code := r.Form.Get("code")
		codeVerifier := r.Form.Get("code_verifier")
		if codeVerifier == "" {
			log.Error("Missing code_verifier in token request")
			s.writeOAuthError(w, "invalid_request", "Missing code_verifier", http.StatusBadRequest)
			return
		}
		if code == "" {
			log.Error("Missing code in token request")
			s.writeOAuthError(w, "invalid_request", "Missing code", http.StatusBadRequest)
			return
		}
		oauthFlow, err := s.authStorage.GetOAuthFlow(clientID)
		if err != nil {
			log.WithError(err).Error("Failed to get oauth flow")
			s.writeOAuthError(w, "server_error", "Server error", http.StatusBadRequest)
			return
		}
		if oauthFlow.AuthCode != code {
			log.Error("Invalid auth code in token request")
			s.writeOAuthError(w, "invalid_grant", "The authorization code is invalid", http.StatusBadRequest)
			return
		}

		// perform PKCE verification
		hash := sha256.Sum256([]byte(codeVerifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
		if oauthFlow.CodeChallenge != codeChallenge {
			log.Error("PKCE verification failed. Invalid code challenge in token request")
			s.writeOAuthError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
			return
		}

		// all good, issue auth token for the given client
		authToken = &auth.AuthToken{
			AccessToken:      utils.NewId(),
			TokenType:        "Bearer",
			ExpiresIn:        s.conf.Auth.OAuth.TokenExpirationSeconds,
			RefreshToken:     utils.NewId(),
			Scope:            oauthFlow.Scope,
			Client:           oauthFlow.RegisteredClient,
			IssuedAt:         time.Now(),
			IntegrationToken: oauthFlow.IntegrationToken,
		}
		if err := s.authStorage.AddAuthToken(authToken); err != nil {
			log.WithError(err).Error("Failed to add auth token")
			s.writeOAuthError(w, "server_error", "Server error", http.StatusBadRequest)
			return
		}
	case "refresh_token":
		refreshToken := r.Form.Get("refresh_token")
		scope := r.Form.Get("scope")
		if refreshToken == "" {
			log.Error("Missing refresh_token in token request")
			s.writeOAuthError(w, "invalid_grant", "Missing refresh_token", http.StatusBadRequest)
			return
		}
		oldToken, err := s.authStorage.GetRefreshToken(refreshToken)
		if err != nil {
			log.WithError(err).Error("Failed to get auth token by refresh token")
			s.writeOAuthError(w, "invalid_grant", "Invalid refresh_token", http.StatusBadRequest)
			return
		}
		// check scope
		if scope != "" && !s.isScopeValid(strings.Split(oldToken.Scope, " "), scope) {
			log.Error("Invalid token scope in token request")
			s.writeOAuthError(w, "invalid_grant", "Invalid token scope", http.StatusBadRequest)
			return
		}
		// all good, issue renewed auth token for the given client
		authToken = &auth.AuthToken{
			AccessToken:      utils.NewId(),
			TokenType:        "Bearer",
			ExpiresIn:        s.conf.Auth.OAuth.TokenExpirationSeconds,
			RefreshToken:     utils.NewId(),
			Scope:            oldToken.Scope,
			Client:           oldToken.Client,
			IssuedAt:         time.Now(),
			IntegrationToken: oldToken.IntegrationToken,
		}
		if err := s.authStorage.RefreshToken(refreshToken, authToken); err != nil {
			log.WithError(err).Error("Failed to refresh token")
			s.writeOAuthError(w, "server_error", "Server error", http.StatusBadRequest)
			return
		}
	default:
		log.WithField("grant_type", grantType).Error("Invalid grant_type")
		s.writeOAuthError(w, "invalid_grant", "Invalid grant_type", http.StatusBadRequest)
		return
	}

	replyAuthToken := &auth.AuthToken{
		AccessToken:  authToken.AccessToken,
		TokenType:    authToken.TokenType,
		ExpiresIn:    authToken.ExpiresIn,
		RefreshToken: authToken.RefreshToken,
		Scope:        authToken.Scope,
		IssuedAt:     authToken.IssuedAt,
	}
	responseJson, err := json.Marshal(replyAuthToken)
	if err != nil {
		log.WithError(err).Error("Failed to marshal auth token")
		s.writeOAuthError(w, "server_error", "Server error", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(http.StatusOK)

	if _, err := fmt.Fprintln(w, string(responseJson)); err != nil {
		log.WithError(err).Error("Failed to write auth token response")
	}
}

func (s *StreamableServer) writeOAuthError(w http.ResponseWriter, err string, message string, code int) {
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(code)
	responseJson, _ := json.Marshal(map[string]any{
		"error":             err,
		"error_description": message,
	})
	if _, err := fmt.Fprintln(w, string(responseJson)); err != nil {
		log.WithError(err).Error("Failed to write auth token response")
	}
}
