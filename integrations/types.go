package integrations

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"

	mcpserver "github.com/mark3labs/mcp-go/server"

	ggl "github.com/mcpbus-io/mcpbus/integrations/google"
)

const (
	integrationGoogle = "google"
)

var SupportedIntegrations = []string{
	integrationGoogle,
}

type Config struct {
	Type   string `json:"type"`
	Config json.RawMessage
}

type Integration interface {
	LoadMCP(server *mcpserver.MCPServer, baseURL string) error
	GetOAuthRedirectURL(state string) string
	ExchangeOauthCode(code string) (*oauth2.Token, error)
}

func (c *Config) GetIntegration() (Integration, error) {
	switch c.Type {
	case integrationGoogle:
		googleIntegration, err := ggl.New(c.Config)
		if err != nil {
			return nil, err
		}
		return googleIntegration, nil
	}

	return nil, fmt.Errorf("unsupported integration type: %s", c.Type)
}
