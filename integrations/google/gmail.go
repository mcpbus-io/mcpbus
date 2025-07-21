package google

import (
	"context"
	"encoding/json"
	"errors"

	mcptypes "github.com/mark3labs/mcp-go/mcp"
	mcpbustypes "github.com/mcpbus-io/mcpbus/types"

	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

func (i *Integration) getLabels(ctx context.Context, request mcptypes.CallToolRequest) (*mcptypes.CallToolResult, error) {
	token := i.getTokenFromContext(ctx)
	if token == nil {
		return mcpbustypes.GetErrorResponse("server error"), errors.New("invalid oauth token or not found in context")
	}

	client := i.getClient(token)

	srv, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return mcpbustypes.GetErrorResponse("unable to create GMail client"), err
	}

	res, err := srv.Users.Labels.List(user).Do()
	if err != nil {
		return mcpbustypes.GetErrorResponse("unable to list labels"), err
	}

	body, err := json.Marshal(res.Labels)
	if err != nil {
		return mcpbustypes.GetErrorResponse("unable to marshal labels"), err
	}

	mcpResult := &mcptypes.CallToolResult{
		Content: []mcptypes.Content{
			mcptypes.TextContent{
				Type: "text",
				Text: string(body),
			},
		},
		IsError: false,
	}

	return mcpResult, nil
}
