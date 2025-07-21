package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/mcpbus-io/mcpbus/backends"
	httpbackend "github.com/mcpbus-io/mcpbus/backends/web/http"

	mcptypes "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

type Tool struct {
	McpInfo McpToolInfo          `json:"mcpInfo"`
	Backend backends.BackendInfo `json:"backend"`
}

type McpToolInfo struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description,omitempty"`
	InputSchema json.RawMessage         `json:"inputSchema"` // TODO: add support for outputSchema
	Annotations mcptypes.ToolAnnotation `json:"annotations"`
}

func GetToolHandler(tool *Tool) (mcpserver.ToolHandlerFunc, error) {
	switch tool.Backend.Type {
	case backends.BackendGolang:
		return handleAddTool, nil // TODO: remove this
	case backends.BackendHttp:
		backend, err := httpbackend.New(
			tool.Backend.Config,
			[]string{
				http.MethodPost, http.MethodGet,
				http.MethodDelete, http.MethodDelete,
			},
		)
		if err != nil {
			return nil, err
		}
		return backend.HandleToolCall, nil
	}

	return nil, errors.New("unknown backend type: " + tool.Backend.Type)
}

func handleAddTool(
	ctx context.Context,
	request mcptypes.CallToolRequest,
) (*mcptypes.CallToolResult, error) {
	arguments := request.GetArguments()
	a, ok1 := arguments["a"].(float64)
	b, ok2 := arguments["b"].(float64)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("invalid number arguments")
	}
	sum := a + b
	return &mcptypes.CallToolResult{
		Content: []mcptypes.Content{
			mcptypes.TextContent{
				Type: "text",
				Text: fmt.Sprintf("The sum of %f and %f is %f.", a, b, sum),
			},
		},
	}, nil
}
