package http

type TlsConfig struct {
	CertFile   string `hcl:"certFile"`
	KeyFile    string `hcl:"keyFile"`
	RootCAFile string `hcl:"rootCAFile"`
}

type Config struct {
	MTls                *TlsConfig        `json:"mTLS"`
	Url                 string            `json:"url"`
	Method              string            `json:"method"`
	AcceptHeader        string            `json:"acceptHeader"`
	ContentTypeHeader   string            `json:"contentType"`
	AuthToken           string            `json:"authToken,omitempty"`
	XHeaders            map[string]string `json:"xHeaders,omitempty"`
	PayloadTemplate     string            `json:"payloadTemplate,omitempty"`
	PayloadTemplateFile string            `json:"payloadTemplateFile,omitempty"`
	GetMethodPayload    bool              `json:"getMethodPayload,omitempty"`
}
