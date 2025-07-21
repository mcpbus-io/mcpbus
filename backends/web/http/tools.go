package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	nativehttp "net/http"

	mcptypes "github.com/mark3labs/mcp-go/mcp"
	mcpbustypes "github.com/mcpbus-io/mcpbus/types"
)

func (b *Backend) HandleToolCall(ctx context.Context, request mcptypes.CallToolRequest) (*mcptypes.CallToolResult, error) {
	req, err := b.prepareRequest(ctx, request.GetArguments())
	if err != nil {
		return mcpbustypes.GetErrorResponse("failed to prepare request"), err
	}

	// send the request to the backend
	resp, err := b.client.Do(req)
	if err != nil {
		return mcpbustypes.GetErrorResponse("failed to send request to backend"), err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= nativehttp.StatusBadRequest {
		return mcpbustypes.GetErrorResponse(fmt.Sprintf("backend returned status code %d", resp.StatusCode)), errors.New(resp.Status)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return mcpbustypes.GetErrorResponse("failed to read response body"), err
	}

	// TODO: add support of image and sound content types

	// TODO: add support for structured output

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

func (b *Backend) prepareRequest(ctx context.Context, arguments map[string]any) (*nativehttp.Request, error) {
	// apply templating to URL
	endpointUrl := b.conf.Url
	if b.urlTemplate != nil {
		var buf bytes.Buffer
		if err := b.urlTemplate.Execute(&buf, arguments); err != nil {
			return nil, errors.Join(errors.New("failed to apply URL template"), err)
		}
		endpointUrl = buf.String()
	}

	// apply templating to payload
	var reqBody io.Reader
	if b.conf.Method == nativehttp.MethodGet && !b.conf.GetMethodPayload {
		// don't send payload in request for GET requests
		reqBody = nil
	} else if b.payloadTemplate != nil {
		// use provided template
		var buf bytes.Buffer
		if err := b.payloadTemplate.Execute(&buf, arguments); err != nil {
			return nil, errors.Join(errors.New("failed to apply payload template"), err)
		}
		reqBody = bytes.NewReader(buf.Bytes())
	} else {
		// we will send tool parameters as is (in the form of JSON) in a payload
		payload, err := json.Marshal(arguments)
		if err != nil {
			return nil, errors.Join(errors.New("failed to marshal tool parameters"), err)
		}
		reqBody = bytes.NewReader(payload)
	}

	req, err := nativehttp.NewRequestWithContext(ctx, b.conf.Method, endpointUrl, reqBody)
	if err != nil {
		return nil, errors.Join(errors.New("failed to create request"), err)
	}

	// escape query string
	query := req.URL.Query()
	req.URL.RawQuery = query.Encode()

	// set headers
	req.Header.Set("User-Agent", "MCPBus web/http backend")
	if b.conf.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+b.conf.AuthToken)
	}
	if b.conf.ContentTypeHeader != "" {
		req.Header.Set("Content-Type", b.conf.ContentTypeHeader)
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.conf.AcceptHeader != "" {
		req.Header.Set("Accept", b.conf.AcceptHeader)
	} else {
		req.Header.Set("Accept", "application/json")
	}
	if len(b.conf.XHeaders) > 0 {
		for k, v := range b.conf.XHeaders {
			req.Header.Set(k, v)
		}
	}

	return req, nil
}
