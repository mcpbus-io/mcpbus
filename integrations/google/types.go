package google

type OauthConfig struct {
	ClientId     string   `json:"clientId,omitempty"`
	ClientSecret string   `json:"clientSecret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

type Config struct {
	Oauth OauthConfig `json:"oauth"`
}
