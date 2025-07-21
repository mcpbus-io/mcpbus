package google

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	mcptypes "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	mcpbustypes "github.com/mcpbus-io/mcpbus/types"
	"golang.org/x/oauth2"
	goauth "golang.org/x/oauth2/google"
)

const (
	user = "me"
)

type Integration struct {
	config      *Config
	redirectUrl string
	clients     map[string]*http.Client
	clientMutex sync.Mutex
}

func New(configData json.RawMessage) (*Integration, error) {
	conf := &Config{}
	err := json.Unmarshal(configData, conf)
	if err != nil {
		return nil, err
	}

	// validate config
	if conf.Oauth.ClientId == "" {
		return nil, errors.New("client_id is required")
	}
	if conf.Oauth.ClientSecret == "" {
		return nil, errors.New("client_secret is required")
	}

	return &Integration{
		config:  conf,
		clients: make(map[string]*http.Client),
	}, nil
}

func (i *Integration) LoadMCP(server *mcpserver.MCPServer, redirectUrl string) error {
	i.redirectUrl = redirectUrl

	mcpTool := mcptypes.NewTool(
		"get_labels",
		mcptypes.WithDescription("Get list of mail box labels"),
		mcptypes.WithToolAnnotation(mcptypes.ToolAnnotation{
			Title:           "Get list of mail box labels",
			ReadOnlyHint:    mcptypes.ToBoolPtr(true),
			DestructiveHint: mcptypes.ToBoolPtr(false),
			IdempotentHint:  mcptypes.ToBoolPtr(false),
			OpenWorldHint:   mcptypes.ToBoolPtr(true),
		}),
	)

	server.AddTool(mcpTool, i.getLabels)

	return nil
}

func (i *Integration) GetOAuthRedirectURL(state string) string {
	conf := i.getConfig()
	return conf.AuthCodeURL(state)
}

func (i *Integration) ExchangeOauthCode(code string) (*oauth2.Token, error) {
	// exchange code for token
	conf := i.getConfig()
	ctx := context.Background()
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	// prepare client
	i.clientMutex.Lock()
	defer i.clientMutex.Unlock()
	client := conf.Client(ctx, tok)
	i.clients[tok.AccessToken] = client

	return tok, nil
}

func (i *Integration) getConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     i.config.Oauth.ClientId,
		ClientSecret: i.config.Oauth.ClientSecret,
		RedirectURL:  i.redirectUrl,
		Scopes:       i.config.Oauth.Scopes,
		Endpoint:     goauth.Endpoint,
	}
}

func (i *Integration) getClient(token *oauth2.Token) *http.Client {
	i.clientMutex.Lock()
	defer i.clientMutex.Unlock()
	client, ok := i.clients[token.AccessToken]
	if !ok {
		config := i.getConfig()
		client = config.Client(context.Background(), token)
		i.clients[token.AccessToken] = client
	}
	return client
}

func (i *Integration) getTokenFromContext(ctx context.Context) *oauth2.Token {
	tokenValue := ctx.Value(mcpbustypes.IntegrationTokenKey{})
	token, ok := tokenValue.(*oauth2.Token)
	if !ok {
		return nil
	}
	return token
}
