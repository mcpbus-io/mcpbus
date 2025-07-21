package auth

import (
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

type AuthStorage interface {
	AddClient(client *RegisterResponse) error
	GetClient(clientID string) (*RegisterResponse, error)
	DeleteClient(clientID string)

	AddOAuthFlow(oauthFlow *OauthFlow) error
	AddOAuthFlowByCode(code string, oauthFlow *OauthFlow) error
	GetOAuthFlow(code string) (*OauthFlow, error)
	DeleteOAuthFlow(code string)
	UpdateOAuthFlow(oauthFlow *OauthFlow) error

	AddAuthToken(oauthToken *AuthToken) error
	GetAuthToken(token string) (*AuthToken, error)
	GetRefreshToken(refreshToken string) (*AuthToken, error)
	DeleteAuthToken(token string)
	RefreshToken(refreshToken string, newToken *AuthToken) error
}

type ClientMetadata struct {
	// RedirectURIs specifies redirection URI strings for use in
	// redirect-based flows such as the "authorization code" and "implicit".
	RedirectURIs []string `json:"redirect_uris,omitempty"`

	// TokenEndpointAuthMethod specifies indicator of the requested authentication
	// method for the token endpoint
	// Possible values are:
	// "none": The client is a public client and does not have a client secret.
	// "client_secret_post": The client uses the HTTP POST parameters
	// "client_secret_basic": The client uses HTTP Basic
	// Additional values can be defined or absolute URIs can also be used
	// as values for this parameter without being registered.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// GrantTypes specifies grant type strings that the client can use at the token endpoint
	// Possible values are:
	// "authorization_code": The authorization code grant type
	// "implicit": The implicit grant type
	// "password": The resource owner password credentials grant type
	// "client_credentials": The client credentials grant type
	// "refresh_token": The refresh token grant type
	// "urn:ietf:params:oauth:grant-type:jwt-bearer": The JWT Bearer Token Grant Type
	// "urn:ietf:params:oauth:grant-type:saml2-bearer": The SAML 2.0 Bearer Assertion Grant
	GrantTypes []string `json:"grant_types,omitempty"`

	// ResponseTypes specifies response type strings that the client can
	// use at the authorization endpoint.
	// Possible values are:
	// "code": The "authorization code" response
	// "token": The "implicit" response
	ResponseTypes []string `json:"response_types,omitempty"`

	// ClientName specifies Human-readable string name of the client
	// to be presented to the end-user during authorization
	ClientName string `json:"client_name,omitempty"`

	// ClientURI specifies URL of a web page providing information about the client.
	ClientURI string `json:"client_uri,omitempty"`

	// LogoURI specifies URL of a logo of the client
	LogoURI string `json:"logo_uri,omitempty"`

	// Scope specifies wire-level scopes representation
	Scope string `json:"scope,omitempty"`

	// Contacts specifies ways to contact people responsible for this client,
	// typically email addresses.
	Contacts []string `json:"contacts,omitempty"`

	// TermsOfServiceURI specifies URL of a human-readable terms of service
	// document for the client
	TermsOfServiceURI string `json:"tos_uri,omitempty"`

	// PolicyURI specifies URL of a human-readable privacy policy document
	PolicyURI string `json:"policy_uri,omitempty"`

	// JWKSURI specifies URL referencing the client's JWK Set [RFC7517] document,
	// which contains the client's public keys.
	JWKSURI string `json:"jwks_uri,omitempty"`

	// JWKS specifies the client's JWK Set [RFC7517] document, which contains
	// the client's public keys.  The value of this field MUST be a JSON
	// containing a valid JWK Set.
	JWKS string `json:"jwks,omitempty"`

	// SoftwareID specifies UUID assigned by the client developer or software publisher
	// used by registration endpoints to identify the client software.
	SoftwareID string `json:"software_id,omitempty"`

	// SoftwareVersion specifies version of the client software
	SoftwareVersion string `json:"software_version,omitempty"`

	// SoftwareStatement specifies client metadata values about the client software
	// as claims.  This is a string value containing the entire signed JWT.
	SoftwareStatement string `json:"software_statement,omitempty"`

	// Optional specifies optional fields
	Optional map[string]string `json:"-"`
}

// Response describes Client Information Response as specified in Section 3.2.1 of RFC 7591
type RegisterResponse struct {
	// ClientID specifies client identifier string. REQUIRED
	ClientID string `json:"client_id"`

	// ClientSecret specifies client secret string. OPTIONAL
	ClientSecret string `json:"client_secret"`

	// ClientIDIssuedAt specifies the time at which the client identifier was issued. OPTIONAL
	ClientIDIssuedAt int64 `json:"client_id_issued_at"`

	// ClientSecretExpiresAt specifies the time at which the client	secret will expire
	// or 0 if it does not expire. REQUIRED if "client_secret" is issued.
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at"`

	// Additionally, the authorization server MUST return all registered metadata about this client
	ClientMetadata `json:",inline"`
}

type OauthFlow struct {
	RegisteredClient    *RegisterResponse `json:"registered_client"`
	RedirectURI         string            `json:"redirect_uri"`
	CodeChallenge       string            `json:"code_challenge"`
	CodeChallengeMethod string            `json:"code_challenge_method"`
	State               string            `json:"state"`
	Scope               string            `json:"scope"`
	AuthCode            string            `json:"auth_code"`
	FinalRedirectURL    *url.URL          `json:"final_redirect_url"`
	IntegrationToken    *oauth2.Token     `json:"integration_token"`
}

type AuthToken struct {
	AccessToken      string            `json:"access_token"`
	TokenType        string            `json:"token_type"`
	ExpiresIn        uint              `json:"expires_in"`
	RefreshToken     string            `json:"refresh_token"`
	Scope            string            `json:"scope"`
	Client           *RegisterResponse `json:"client,omitempty"`
	IssuedAt         time.Time         `json:"issued_at"`
	IntegrationToken *oauth2.Token     `json:"integration_token,omitempty"`
}
