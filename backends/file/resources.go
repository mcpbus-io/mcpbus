package file

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mcpbus-io/mcpbus/backends"
	"os"
	"path/filepath"
	"strings"

	mcptypes "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/yosida95/uritemplate/v3"

	"github.com/mcpbus-io/mcpbus/utils"
)

func (b *Backend) GetResourceHandler(uriTemplate *uritemplate.Template, mimeTypeConf string) server.ResourceHandlerFunc {
	return func(ctx context.Context, request mcptypes.ReadResourceRequest) ([]mcptypes.ResourceContents, error) {
		// apply template with arguments to the path if required
		arguments := utils.GetArgumentsFromURI(uriTemplate, request.Params.URI)
		path := b.conf.Path
		if b.pathTemplate != nil {
			var buf bytes.Buffer
			if err := b.pathTemplate.Execute(&buf, arguments); err != nil {
				return nil, errors.Join(errors.New("failed to apply path template"), err)
			}
			path = buf.String()
		}

		fileInfo, err := os.Stat(path)
		if err != nil {
			return nil, err
		}

		if !fileInfo.IsDir() {
			// we have a regular file
			resourceContents, err := GetFileAsResource(
				path,
				request.Params.URI,
				mimeTypeConf,
			)
			if err != nil {
				return nil, err
			}
			return []mcptypes.ResourceContents{resourceContents}, nil
		}

		// we have a directory
		// read dir
		dir, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}

		// prepare reply
		result := make([]mcptypes.ResourceContents, 0, len(dir))
		for _, entry := range dir {
			if entry.IsDir() {
				dirURI := request.Params.URI + "/" + entry.Name()
				dirContents, err := b.getSubDirContents(dirURI, filepath.Join(path, entry.Name()))
				if err != nil {
					return nil, err
				}
				resourceContents := mcptypes.TextResourceContents{
					URI:  dirURI,
					Text: dirContents,
				}
				result = append(result, resourceContents)
			} else {
				resourceContents, err := GetFileAsResource(
					filepath.Join(path, entry.Name()),
					request.Params.URI+"/"+entry.Name(),
					mimeTypeConf,
				)
				if err != nil {
					return nil, err
				}
				result = append(result, resourceContents)
			}
		}

		return result, nil
	}
}

func (b *Backend) GetDynamicResources(uri string, mimeTypeConf string) ([]backends.DynamicResource, error) {
	// apply template with arguments to the path if required
	if !b.conf.EnableWalkthrough {
		return nil, nil
	}

	rootPath := b.conf.Path

	fileInfo, err := os.Stat(rootPath)
	if err != nil {
		return nil, err
	}

	// return nothing if this is file
	if !fileInfo.IsDir() {
		return nil, nil
	}

	resources := make([]backends.DynamicResource, 0, 10)

	// walkthrough the root path
	visit := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		filePath := strings.TrimPrefix(path, rootPath)
		fileUri := uri + filepath.ToSlash(filePath)
		backendInfo := backends.BackendInfo{
			Type:   backends.BackendFile,
			Config: json.RawMessage(fmt.Sprintf(`{"path": "%s"}`, path)),
		}

		if d.IsDir() {
			resources = append(resources, backends.DynamicResource{
				URI:         fileUri,
				Name:        filePath,
				Description: "Directory " + filePath,
				Backend:     backendInfo,
			})
		} else {
			desc := "File " + filePath
			// read the head of a file to determine MIME and use it in description if configured
			buf := make([]byte, 512)
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			descEnding := ""
			if n, err := f.Read(buf); err != nil {
				return err
			} else if n < 512 {
				buf = buf[:n]
				descEnding = "..."
			}
			if b.conf.FileHeadInDesc {
				desc = string(buf) + descEnding
			}
			detectedMime := utils.DetectMime(filePath, buf, mimeTypeConf)
			resources = append(resources, backends.DynamicResource{
				URI:         fileUri,
				Name:        filePath,
				Description: desc,
				MIMEType:    detectedMime,
				Backend:     backendInfo,
			})
		}

		return nil
	}

	err = filepath.WalkDir(rootPath, visit)
	if err != nil {
		return nil, err
	}

	return resources, nil
}

func (b *Backend) getSubDirContents(dirURI string, path string) (string, error) {
	dir, err := os.ReadDir(path)
	if err != nil {
		return "", err
	}
	result := ""
	for _, entry := range dir {
		result += dirURI + "/" + entry.Name() + "\n"
	}

	return result, nil
}
