package file

import (
	"encoding/base64"
	mcptypes "github.com/mark3labs/mcp-go/mcp"
	"os"

	"github.com/mcpbus-io/mcpbus/utils"
)

func GetFileAsResource(path string, uri string, mimeConf string) (mcptypes.ResourceContents, error) {
	// read file contents
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// detect MIME
	detectedMime := utils.DetectMime(path, data, mimeConf)

	if utils.IsText(detectedMime) {
		// we have a text resource
		return mcptypes.TextResourceContents{
			URI:      uri,
			MIMEType: detectedMime,
			Text:     string(data),
		}, nil
	}

	// we have a binary resource
	return mcptypes.BlobResourceContents{
		URI:      uri,
		MIMEType: detectedMime,
		Blob:     base64.StdEncoding.EncodeToString(data),
	}, nil
}
