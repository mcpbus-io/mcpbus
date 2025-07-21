package mcp

type InitializeRequest struct {
	JsonRpc string                  `json:"jsonrpc"`
	Method  string                  `json:"method"`
	Params  initializeRequestParams `json:"params"`
	Id      any                     `json:"id,omitempty"`
}

type initializeRequestParams struct {
	ProtocolVersion string        `json:"protocolVersion"`
	Capabilities    *capabilities `json:"capabilities"`
	ClientInfo      *clientInfo   `json:"clientInfo"`
}

type capabilities struct {
	Roots    *capRoots    `json:"roots"`
	Sampling *capSampling `json:"sampling"`
	Client   *clientInfo  `json:"clientInfo"`
}

type capRoots struct {
	ListChanged *bool `json:"listChanged,omitempty"`
}

type capSampling struct {
	ListChanged *bool `json:"listChanged,omitempty"`
}

type clientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InitializeResponse struct {
	JsonRpc string            `json:"jsonrpc"`
	Result  *initializeResult `json:"result,omitempty"`
	Id      any               `json:"id,omitempty"`
}

type initializeResult struct {
	ProtocolVersion string              `json:"protocolVersion"`
	Capabilities    *serverCapabilities `json:"capabilities"`
	ServerInfo      *serverInfo         `json:"serverInfo"`
	Instructions    string              `json:"instructions"`
}

type serverCapabilities struct {
	Logging   *struct{}  `json:"logging,omitempty"`
	Prompts   *serverCap `json:"prompts,omitempty"`
	Resources *serverCap `json:"resources,omitempty"`
	Tools     *serverCap `json:"tools,omitempty"`
}

type serverCap struct {
	Subscribe   *bool `json:"subscribe,omitempty"`
	ListChanged bool  `json:"listChanged"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
