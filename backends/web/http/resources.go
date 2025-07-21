package http

import (
	"context"
	"encoding/base64"
	"errors"
	mcptypes "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/mcpbus-io/mcpbus/backends"
	"github.com/mcpbus-io/mcpbus/utils"
	"github.com/yosida95/uritemplate/v3"
	"io"
	"mime"
	nativehttp "net/http"
)

func (b *Backend) GetResourceHandler(uriTemplate *uritemplate.Template, mimeTypeConf string) server.ResourceHandlerFunc {
	return func(ctx context.Context, request mcptypes.ReadResourceRequest) ([]mcptypes.ResourceContents, error) {
		arguments := utils.GetArgumentsFromURI(uriTemplate, request.Params.URI)

		req, err := b.prepareRequest(ctx, arguments)
		if err != nil {
			return nil, err
		}

		// send the request to the backend
		resp, err := b.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode >= nativehttp.StatusBadRequest {
			return nil, errors.New(resp.Status)
		}

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		mimeType := ""
		if contentType := resp.Header.Get("Content-Type"); contentType == "" {
			mimeType = nativehttp.DetectContentType(body)
		} else {
			mediaType, _, err := mime.ParseMediaType(contentType)
			if err == nil {
				mimeType = mediaType
			}
		}

		// set the one from config if MIME wasn't determined
		if mimeType == "" {
			mimeType = mimeTypeConf // it could still be empty though
		}

		if utils.IsText(mimeType) {
			// we have a text resource
			resourceContents := mcptypes.TextResourceContents{
				URI:      request.Params.URI,
				MIMEType: mimeType,
				Text:     string(body),
			}
			return []mcptypes.ResourceContents{resourceContents}, nil
		}

		// we have binary resource
		blobResourceContents := mcptypes.BlobResourceContents{
			URI:      request.Params.URI,
			MIMEType: mimeType,
			Blob:     base64.StdEncoding.EncodeToString(body),
		}
		return []mcptypes.ResourceContents{blobResourceContents}, nil
	}
}

func (b *Backend) GetDynamicResources(uri string, mimeTypeConf string) ([]backends.DynamicResource, error) {
	return nil, nil
}
