package types

import mcptypes "github.com/mark3labs/mcp-go/mcp"

type TokenKey struct{}

type IntegrationTokenKey struct{}

func GetErrorResponse(message string) *mcptypes.CallToolResult {
	return &mcptypes.CallToolResult{
		IsError: true,
		Content: []mcptypes.Content{
			mcptypes.TextContent{
				Type: "text",
				Text: message,
			},
		},
	}
}
