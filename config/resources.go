package config

import (
	"errors"
	"net/http"

	mcptypes "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/yosida95/uritemplate/v3"

	"github.com/mcpbus-io/mcpbus/backends"
	filebackend "github.com/mcpbus-io/mcpbus/backends/file"
	httpbackend "github.com/mcpbus-io/mcpbus/backends/web/http"
)

type McpResourceInfo struct {
	mcptypes.Annotated
	URI         string                `json:"uri,omitempty"`
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	MIMEType    string                `json:"mimeType,omitempty"`
	URITemplate *uritemplate.Template // this gets initialized only if read URI field contains template
}

type Resource struct {
	McpInfo McpResourceInfo      `json:"mcpInfo"`
	Backend backends.BackendInfo `json:"backend"`
}

type ResourceBackend interface {
	GetResourceHandler(uriTemplate *uritemplate.Template, mimeTypeConf string) mcpserver.ResourceHandlerFunc
	GetDynamicResources(uri string, mimeTypeConf string) ([]backends.DynamicResource, error)
}

func GetResourceHandler(resource *Resource) (mcpserver.ResourceHandlerFunc, error) {
	var backend ResourceBackend
	var err error
	switch resource.Backend.Type {
	case backends.BackendHttp:
		backend, err = httpbackend.New(resource.Backend.Config, []string{http.MethodPost, http.MethodGet})
		if err != nil {
			return nil, err
		}
	case backends.BackendFile:
		backend, err = filebackend.New(resource.Backend.Config)
		if err != nil {
			return nil, err
		}
	}

	if backend == nil {
		return nil, errors.New("unknown backend type: " + resource.Backend.Type)
	}

	return backend.GetResourceHandler(resource.McpInfo.URITemplate, resource.McpInfo.MIMEType), nil
}

func GetDynamicResources(resource *Resource) ([]*Resource, error) {
	var backend ResourceBackend
	var err error
	switch resource.Backend.Type {
	case backends.BackendHttp:
		backend, err = httpbackend.New(resource.Backend.Config, []string{http.MethodPost, http.MethodGet})
		if err != nil {
			return nil, err
		}
	case backends.BackendFile:
		backend, err = filebackend.New(resource.Backend.Config)
		if err != nil {
			return nil, err
		}
	}

	if backend == nil {
		return nil, errors.New("unknown backend type: " + resource.Backend.Type)
	}

	dynamicResources, err := backend.GetDynamicResources(resource.McpInfo.URI, resource.McpInfo.MIMEType)
	if err != nil {
		return nil, err
	}

	if len(dynamicResources) == 0 {
		return []*Resource{}, nil
	}

	resources := make([]*Resource, 0, len(dynamicResources))
	for _, dynamicResource := range dynamicResources {
		resources = append(resources, &Resource{
			McpInfo: McpResourceInfo{
				Annotated:   resource.McpInfo.Annotated,
				URI:         dynamicResource.URI,
				Name:        dynamicResource.Name,
				Description: dynamicResource.Description,
				MIMEType:    dynamicResource.MIMEType,
			},
			Backend: dynamicResource.Backend,
		})
	}

	return resources, nil
}
