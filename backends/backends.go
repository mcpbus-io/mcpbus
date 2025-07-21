package backends

import "encoding/json"

const (
	BackendGolang = "golang"
	BackendHttp   = "web/http"
	BackendFile   = "file"
)

type BackendInfo struct {
	Type   string `json:"type"`
	Config json.RawMessage
}

type DynamicResource struct {
	URI         string
	Name        string
	Description string
	MIMEType    string
	Backend     BackendInfo
}
