package utils

import (
	"mime"
	"net/http"
	"path/filepath"
	"strings"
)

func IsText(mimeType string) bool {
	return strings.HasPrefix(mimeType, "text/") ||
		strings.HasSuffix(mimeType, "/json") ||
		strings.HasSuffix(mimeType, "/xml") ||
		strings.HasSuffix(mimeType, "+json") ||
		strings.HasSuffix(mimeType, "+xml")
}

func IsPdf(mimeType string) bool {
	return strings.HasSuffix(mimeType, "/pdf") ||
		strings.HasSuffix(mimeType, "+pdf")
}

func DetectMime(path string, data []byte, defaultMime string) string {
	detectedMime := ""

	// try file extension
	if fileExt := filepath.Ext(path); fileExt != "" {
		detectedMime = mime.TypeByExtension(fileExt[1:])
		if detectedMime != "" {
			mediaType, _, err := mime.ParseMediaType(detectedMime)
			if err == nil {
				detectedMime = mediaType
			}
		}
	}

	// try data signature
	if detectedMime == "" && data != nil {
		detectedMime = http.DetectContentType(data)
	}

	// backup to a passed default
	if detectedMime == "" {
		detectedMime = defaultMime
	}

	return detectedMime
}
