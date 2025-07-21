package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yosida95/uritemplate/v3"
	"slices"
	"strings"

	"github.com/mcpbus-io/mcpbus/integrations"
)

const defaultBufferSize = 1024

const defaultConfig string = `{
	"hostName": "localhost",
	"addr": "localhost",
	"port": 8080,
	"mcpEndpoint": "/mcp",
	"auth": {
		"oauth": {
			"tokenExpirationSeconds": 3600
		}
	},
	"disableStreamResume": true,
	"streamBufferSize": 1024,
	"authStorage": {
		"type": "inmemory"
	},
	"sessionStorage": {
		"type": "inmemory"
	},
	"eventsStorage": {
		"type": "inmemory"
	},
	"keepAlivePing": false,
	"mcp": {
		"tools": [],
		"prompts": [],
		"resources": []
	}
}
`

type AuthStorageConfig struct {
	Type          string `json:"type"`
	ExpireSeconds uint   `json:"expireSeconds"`
}

type SessionsStorageConfig struct {
	Type          string `json:"type"`
	ExpireSeconds uint   `json:"expireSeconds"`
}

type EventsStorageConfig struct {
	Type          string `json:"type"`
	ExpireSeconds uint   `json:"expireSeconds"`
}

type TlsConfig struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type AuthorizationServerMetadataConfig struct {
	DisablePublicClients bool `json:"disablePublicClients"`
}

type OAuthConfig struct {
	TokenExpirationSeconds      uint                              `json:"tokenExpirationSeconds"`
	AuthorizationServerMetadata AuthorizationServerMetadataConfig `json:"authorizationServerMetadata"`
}

type AuthConfig struct {
	AuthToken string       `json:"authToken"`
	OAuth     *OAuthConfig `json:"oauth"`
}

type CorsConfig struct {
	AllowedOrigins []string `json:"allowedOrigins"`
}

type RedisConfig struct {
	Addr     string `json:"addr"`
	Username string `json:"username"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

type McpConfig struct {
	LoggingCapability bool                 `json:"loggingCapability"`
	Prompts           []*Prompt            `json:"prompts"`
	Resources         []*Resource          `json:"resources"`
	Tools             []*Tool              `json:"tools"`
	Integration       *integrations.Config `json:"integration"`
}

type Config struct {
	HostName            string                 `json:"hostName"`
	Addr                string                 `json:"addr"`
	Port                uint                   `json:"port"`
	McpEndpoint         string                 `json:"mcpEndpoint"`
	Tls                 *TlsConfig             `json:"tls"`
	Auth                *AuthConfig            `json:"auth"`
	DisableStreaming    bool                   `json:"disableStreaming"`
	DisableStreamResume bool                   `json:"disableStreamResume"`
	StreamBufferSize    uint                   `json:"streamBufferSize"`
	Cors                *CorsConfig            `json:"cors"`
	Redis               *RedisConfig           `json:"redis"`
	SessionsStorage     *SessionsStorageConfig `json:"sessionStorage"`
	EventsStorage       *EventsStorageConfig   `json:"eventsStorage"`
	AuthStorage         *AuthStorageConfig     `json:"authStorage"`
	KeepAlivePing       bool                   `json:"keepAlivePing"`
	Mcp                 *McpConfig             `json:"mcp"`
}

// LoadConfig loads and validates the server configuration
func LoadConfig(configData []byte) (*Config, error) {
	var config Config
	if configData == nil {
		configData = []byte(defaultConfig)
	}
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, errors.Join(errors.New("failed to parse config"), err)
	}

	// Validate configuration
	if config.Addr == "" {
		return nil, errors.New("server address cannot be empty")
	}
	if config.Port == 0 {
		return nil, errors.New("server port cannot be 0")
	}
	if config.McpEndpoint == "" {
		return nil, errors.New("MCP endpoint cannot be empty")
	}
	if config.Mcp == nil {
		return nil, errors.New("MCP configuration cannot be empty")
	}
	if config.HostName == "" {
		config.HostName = "localhost"
	}
	if config.Auth != nil && config.Auth.OAuth != nil && config.Auth.AuthToken != "" {
		return nil, errors.New(`cannot use both "auth_token"" and "oauth" methods at the same time`)
	}
	if config.StreamBufferSize == 0 {
		config.StreamBufferSize = defaultBufferSize
	}

	// prepare resources
	preparedResources := make([]*Resource, 0, len(config.Mcp.Resources))
	for _, resource := range config.Mcp.Resources {
		// compile URI template
		if strings.Contains(resource.McpInfo.URI, "{") {
			// we have a templated URI resource
			uriTemplate, err := uritemplate.New(resource.McpInfo.URI) // rfc6570
			if err != nil {
				return nil, err
			}
			resource.McpInfo.URITemplate = uriTemplate
		}
		// add dynamic resources if the backend provides ones
		dynamicResources, err := GetDynamicResources(resource)
		if err != nil {
			return nil, err
		}
		if len(dynamicResources) > 0 {
			// if config of resource leads to dynamic resources, then we replace it with the returned list
			preparedResources = append(preparedResources, dynamicResources...)
		} else {
			// no dynamic resources, just add resources from initial config
			preparedResources = append(preparedResources, resource)
		}
	}
	config.Mcp.Resources = preparedResources

	// Validate integration
	if config.Mcp.Integration != nil {
		if !slices.Contains(integrations.SupportedIntegrations, config.Mcp.Integration.Type) {
			return nil, fmt.Errorf(`integration type "%s" is not supported`, config.Mcp.Integration.Type)
		}
	}

	return &config, nil
}
