package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	mcptypes "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mcpbus-io/mcpbus/config"
	"github.com/mcpbus-io/mcpbus/integrations"
	"github.com/mcpbus-io/mcpbus/jsonrpc"
	"github.com/mcpbus-io/mcpbus/storages"
	"github.com/mcpbus-io/mcpbus/storages/auth"
	"github.com/mcpbus-io/mcpbus/storages/events"
	"github.com/mcpbus-io/mcpbus/storages/sessions"
	mcpbustypes "github.com/mcpbus-io/mcpbus/types"
	"github.com/mcpbus-io/mcpbus/utils"
	"github.com/redis/go-redis/v9"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

const (
	mcpVersion               = "2025-03-26"
	mcpSessionIdHeader       = "Mcp-Session-Id"
	mcpProtocolVersionHeader = "Mcp-Protocol-Version"

	mpcMethodInitialize  = "initialize"
	mpcMethodInitialized = "notifications/initialized"
	mpcMethodPing        = "ping"

	lastEventIdHeader = "Last-Event-Id"

	eventStreamContentType = "text/event-stream"
	jsonContentType        = "application/json"

	ServerName    = "MCPBus"
	ServerVersion = "0.0.1"
)

type metaDataConf struct {
	Issuer                        string   `json:"issuer"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	JwksUri                       string   `json:"jwks_uri"`
	ScopesSupported               []string `json:"scopes_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	UserinfoEndpoint              string   `json:"userinfo_endpoint"`
	RevocationEndpoint            string   `json:"revocation_endpoint"`
	IntrospectionEndpoint         string   `json:"introspection_endpoint"`
}

type StreamableServer struct {
	conf        *config.Config
	mcpServer   *mcpserver.MCPServer
	sessions    sessions.SessionsStorage
	streams     *StreamsStorage
	events      events.Storage
	authStorage auth.AuthStorage
	baseUrl     string
	metaData    metaDataConf
	integration integrations.Integration
}

func NewStreamableServer(conf *config.Config) (*StreamableServer, error) {
	hooks := &mcpserver.Hooks{}

	hooks.AddBeforeAny(func(ctx context.Context, id any, method mcptypes.MCPMethod, message any) {
		fmt.Printf("beforeAny: %s, %v, %v\n", method, id, message)
	})
	hooks.AddOnSuccess(func(ctx context.Context, id any, method mcptypes.MCPMethod, message any, result any) {
		fmt.Printf("onSuccess: %s, %v, %v, %v\n", method, id, message, result)
	})
	hooks.AddOnError(func(ctx context.Context, id any, method mcptypes.MCPMethod, message any, err error) {
		fmt.Printf("onError: %s, %v, %v, %v\n", method, id, message, err)
	})
	hooks.AddAfterCallTool(func(ctx context.Context, id any, message *mcptypes.CallToolRequest, result *mcptypes.CallToolResult) {
		fmt.Printf("afterCallTool: %v, %v, %v\n", id, message, result)
	})
	hooks.AddBeforeCallTool(func(ctx context.Context, id any, message *mcptypes.CallToolRequest) {
		fmt.Printf("beforeCallTool: %v, %v\n", id, message)
	})

	// this might be used in OAuth endpoints
	baseUrl := ""
	if conf.Tls != nil {
		baseUrl = "https://"
	} else {
		baseUrl = "http://"
	}
	baseUrl += conf.HostName
	if conf.Port != 80 {
		baseUrl = fmt.Sprintf("%s:%d", baseUrl, conf.Port)
	}

	server := &StreamableServer{
		conf: conf,
		mcpServer: mcpserver.NewMCPServer(
			ServerName,
			ServerVersion,
			mcpserver.WithHooks(hooks),
		),
		baseUrl: baseUrl,
		streams: NewStreamsStorage(),
		// TODO: make endpoints configurable
		metaData: metaDataConf{
			Issuer:                        baseUrl,
			RegistrationEndpoint:          baseUrl + oauthRegisterEndpoint,
			AuthorizationEndpoint:         baseUrl + oauthAuthorizeEndpoint,
			TokenEndpoint:                 baseUrl + oauthTokenEndpoint,
			ScopesSupported:               []string{"read", "write", "manage"},
			GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
			ResponseTypesSupported:        []string{"code", "token"},
			CodeChallengeMethodsSupported: []string{"S256"},
			/*
				JwksUri:                       baseUrl + "/oauth/jwks",
				UserinfoEndpoint:              baseUrl + "/userinfo",
				RevocationEndpoint:            baseUrl + "/revoke",
				IntrospectionEndpoint:         baseUrl + "/introspect",

			*/
		},
	}

	if err := server.loadMcpConfig(); err != nil {
		return nil, err
	}

	return server, nil
}

func (s *StreamableServer) loadMcpConfig() error {
	// load prompts
	for _, prompt := range s.conf.Mcp.Prompts {
		s.mcpServer.AddPrompt(prompt.Prompt, s.getPromptHandler(prompt))
	}

	// load resources
	for _, resConf := range s.conf.Mcp.Resources {
		if resConf.McpInfo.URITemplate != nil {
			// we have a templated URI resource
			templatedResource := mcptypes.ResourceTemplate{
				Annotated:   resConf.McpInfo.Annotated,
				URITemplate: &mcptypes.URITemplate{Template: resConf.McpInfo.URITemplate},
				Name:        resConf.McpInfo.Name,
				Description: resConf.McpInfo.Description,
				MIMEType:    resConf.McpInfo.MIMEType,
			}
			handler, err := config.GetResourceHandler(resConf)
			if err != nil {
				return err
			}
			s.mcpServer.AddResourceTemplate(templatedResource, mcpserver.ResourceTemplateHandlerFunc(handler))
		} else {
			// we have a regular resource
			resource := mcptypes.NewResource(resConf.McpInfo.URI, resConf.McpInfo.Name)
			resource.Annotated = resConf.McpInfo.Annotated
			resource.Description = resConf.McpInfo.Description
			resource.MIMEType = resConf.McpInfo.MIMEType
			handler, err := config.GetResourceHandler(resConf)
			if err != nil {
				return err
			}
			s.mcpServer.AddResource(resource, handler)
		}
	}

	// load tools
	for _, tool := range s.conf.Mcp.Tools {
		mcpTool := mcptypes.NewToolWithRawSchema(tool.McpInfo.Name, tool.McpInfo.Description, tool.McpInfo.InputSchema)
		mcpTool.Annotations = tool.McpInfo.Annotations
		toolHandler, err := config.GetToolHandler(tool)
		if err != nil {
			log.Errorf("Failed to get handler for tool %s: %v", tool.McpInfo.Name, err)
			return err
		}
		if tool.McpInfo.InputSchema == nil {
			log.Errorf("Input schema for tool %s is not provided", tool.McpInfo.Name)
			return errors.New("input schema is not provided")
		}
		s.mcpServer.AddTool(mcpTool, toolHandler)
	}

	// load integration
	if s.conf.Mcp.Integration != nil {
		integration, err := s.conf.Mcp.Integration.GetIntegration()
		if err != nil {
			return err
		}
		err = integration.LoadMCP(s.mcpServer, s.baseUrl+oauthIntegrationAuthorizeEndpoint)
		if err != nil {
			return err
		}
		s.integration = integration
	}

	return nil
}

func (s *StreamableServer) getPromptHandler(prompt *config.Prompt) mcpserver.PromptHandlerFunc {
	return func(ctx context.Context, request mcptypes.GetPromptRequest) (*mcptypes.GetPromptResult, error) {
		promptResult := &mcptypes.GetPromptResult{
			Description: prompt.ResultTemplate.Description,
			Messages:    make([]mcptypes.PromptMessage, len(prompt.ResultTemplate.Messages)),
		}

		for i, templateMsg := range prompt.ResultTemplate.Messages {
			msg := mcptypes.PromptMessage{
				Role: mcptypes.Role(templateMsg.Role),
			}

			if len(request.Params.Arguments) > 0 {
				// apply templating only if prompt has parameters
				switch m := templateMsg.Content.(type) {
				case *mcptypes.TextContent:
					content := &mcptypes.TextContent{
						Annotated: m.Annotated,
						Type:      m.Type,
					}
					if templateMsg.TextTemplate != nil {
						var buf bytes.Buffer
						if err := templateMsg.TextTemplate.Execute(&buf, request.Params.Arguments); err != nil {
							return nil, err
						}
						content.Text = buf.String()
					} else {
						content.Text = m.Text
					}
					msg.Content = content
				case *mcptypes.ImageContent:
					msg.Content = m
				case *mcptypes.AudioContent:
					msg.Content = m
				case *mcptypes.EmbeddedResource:
					content := &mcptypes.EmbeddedResource{
						Annotated: m.Annotated,
						Type:      m.Type,
					}
					switch r := m.Resource.(type) {
					case *mcptypes.TextResourceContents:
						res := &mcptypes.TextResourceContents{
							MIMEType: r.MIMEType,
						}
						if templateMsg.TextTemplate != nil {
							var buf bytes.Buffer
							if err := templateMsg.TextTemplate.Execute(&buf, request.Params.Arguments); err != nil {
								return nil, err
							}
							res.Text = buf.String()
						} else {
							res.Text = r.Text
						}
						if templateMsg.URITemplate != nil {
							var buf bytes.Buffer
							if err := templateMsg.URITemplate.Execute(&buf, request.Params.Arguments); err != nil {
								return nil, err
							}
							res.URI = buf.String()
						} else {
							res.URI = r.URI
						}
						content.Resource = res
					case *mcptypes.BlobResourceContents:
						res := &mcptypes.BlobResourceContents{
							MIMEType: r.MIMEType,
							Blob:     r.Blob,
						}
						if templateMsg.URITemplate != nil {
							var buf bytes.Buffer
							if err := templateMsg.URITemplate.Execute(&buf, request.Params.Arguments); err != nil {
								return nil, err
							}
							res.URI = buf.String()
						} else {
							res.URI = r.URI
						}
						content.Resource = res
					default:
						return nil, fmt.Errorf("unsupported resource type: %T", m.Resource)
					}
					msg.Content = content
				default:
					return nil, fmt.Errorf("unsupported content type: %T", m)
				}
			} else {
				msg.Content = templateMsg.Content
			}

			promptResult.Messages[i] = msg
		}

		return promptResult, nil
	}
}

func (s *StreamableServer) Start() error {
	// connect to redis
	var rdb *redis.Client
	if s.conf.Redis != nil {
		opts := &redis.Options{
			Addr: s.conf.Redis.Addr,
		}
		if s.conf.Redis.Username != "" {
			opts.Username = s.conf.Redis.Username
		}
		if s.conf.Redis.Password != "" {
			opts.Password = s.conf.Redis.Password
		}
		if s.conf.Redis.DB != 0 {
			opts.DB = s.conf.Redis.DB
		}
		rdb = redis.NewClient(opts)
		if err := rdb.Ping(context.Background()).Err(); err != nil {
			return err
		}
		defer rdb.Close()
	}

	// set session storage
	switch s.conf.SessionsStorage.Type {
	case storages.InMemoryStorageType:
		s.sessions = sessions.NewInMemorySessionsStorage()
	case storages.RedisStorageType:
		if rdb == nil {
			return errors.New("redis storage is not configured")
		}
		s.sessions = sessions.NewRedisStorage(rdb, time.Second*time.Duration(s.conf.SessionsStorage.ExpireSeconds))
	default:
		return fmt.Errorf("unknown sessions storage type: %s", s.conf.SessionsStorage.Type)
	}

	// set auth storage
	switch s.conf.AuthStorage.Type {
	case storages.InMemoryStorageType:
		s.authStorage = auth.NewInMemoryAuthStorage()
	case storages.RedisStorageType:
		s.authStorage = auth.NewRedisStorage(rdb, time.Second*time.Duration(s.conf.AuthStorage.ExpireSeconds))
	default:
		return fmt.Errorf("unknown streams storage type: %s", s.conf.AuthStorage.Type)
	}

	// set events storage
	switch s.conf.EventsStorage.Type {
	case storages.InMemoryStorageType:
		s.events = events.NewInMemory()
	case storages.RedisStorageType:
		s.events = events.NewRedisStorage(rdb, time.Second*time.Duration(s.conf.EventsStorage.ExpireSeconds))
	default:
		return fmt.Errorf("unknown streams storage type: %s", s.conf.EventsStorage.Type)
	}

	// configure CORS
	var c *cors.Cors
	if s.conf.Cors != nil {
		// TODO: populate it properly from config
		c = cors.New(cors.Options{
			AllowedOrigins: s.conf.Cors.AllowedOrigins,
		})
	} else {
		c = cors.AllowAll()
	}
	c.Log = log.StandardLogger()

	// main MCP endpoint
	http.HandleFunc(s.conf.McpEndpoint, c.Handler(http.HandlerFunc(s.mainHandler)).ServeHTTP)

	// add SMP and OAuth if configured
	if s.conf.Auth != nil && s.conf.Auth.OAuth != nil {
		// Auth SMP endpoint
		http.HandleFunc(smpEndpoint, c.Handler(http.HandlerFunc(s.smpHandler)).ServeHTTP)

		// oauth endpoints
		http.HandleFunc(oauthRegisterEndpoint, c.Handler(http.HandlerFunc(s.oauthRegisterHandler)).ServeHTTP)
		http.HandleFunc(oauthAuthorizeEndpoint, c.Handler(http.HandlerFunc(s.oauthAuthorizeHandler)).ServeHTTP)
		http.HandleFunc(oauthTokenEndpoint, c.Handler(http.HandlerFunc(s.oauthTokenHandler)).ServeHTTP)
		if s.conf.Mcp.Integration != nil {
			http.HandleFunc(oauthIntegrationAuthorizeEndpoint, s.oauthIntegrationAuthHandler)
		}
	}

	addr := fmt.Sprintf("%s:%d", s.conf.Addr, s.conf.Port)

	if s.conf.Tls != nil {
		return http.ListenAndServeTLS(addr, s.conf.Tls.CertFile, s.conf.Tls.KeyFile, nil)
	}

	return http.ListenAndServe(addr, nil)
}

func (s *StreamableServer) addCommonHeaders(w http.ResponseWriter) {
	w.Header().Set("Server", ServerName+"/"+ServerVersion)
}

func (s *StreamableServer) mainHandler(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{
		"method":      r.Method,
		"path":        r.URL.Path,
		"remote_addr": r.RemoteAddr,
		"user_agent":  r.UserAgent(),
	}).Info("Handling request")

	// perform auth
	req := r
	if token, ok := s.authenticateRequest(w, r); !ok {
		log.WithFields(log.Fields{}).Error("Authentication failed")
		return
	} else if token != nil {
		newCtx := context.WithValue(r.Context(), mcpbustypes.TokenKey{}, token)
		if token.IntegrationToken != nil {
			newCtx = context.WithValue(newCtx, mcpbustypes.IntegrationTokenKey{}, token.IntegrationToken)
		}
		req = r.WithContext(newCtx)
	}

	s.addCommonHeaders(w)

	switch r.Method {
	case http.MethodPost: // new JSON-RPC message
		s.handlePostRequest(w, req)
	case http.MethodGet: // the client wants to open SSE stream to listen for the messages from the server
		s.handleGetRequest(w, req)
	case http.MethodDelete: // the client wants to delete MCP-session
		s.handleDeleteRequest(w, req)
	default: // the supplied method is not supported
		s.handleUnsupportedRequest(w, req)
	}
}

func (s *StreamableServer) authenticateRequest(w http.ResponseWriter, r *http.Request) (*auth.AuthToken, bool) {
	if s.conf.Auth == nil {
		return nil, true
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		s.writeOAuthError(w, "invalid_request", "Invalid authorization header format", http.StatusBadRequest)
		return nil, false
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		s.writeOAuthError(w, "invalid_request", "Invalid authorization header format", http.StatusBadRequest)
		return nil, false
	}

	if s.conf.Auth.OAuth != nil {
		token, err := s.authStorage.GetAuthToken(authHeaderParts[1])
		if err != nil {
			s.writeOAuthError(w, "invalid_token", "invalid access token", http.StatusUnauthorized)
			return nil, false
		} else {
			return token, true
		}
	} else if s.conf.Auth.AuthToken != authHeaderParts[1] {
		s.writeOAuthError(w, "invalid_token", "invalid access token", http.StatusUnauthorized)
		return nil, false
	}

	return nil, true
}

func (s *StreamableServer) handlePostRequest(w http.ResponseWriter, r *http.Request) {
	// check that both application/json and text/event-stream are accepted
	acceptHeader, present := r.Header["Accept"]
	if !present {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Accept header must be provided", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusNotAcceptable,
		)
		return
	} else if len(acceptHeader) == 1 {
		acceptHeader = strings.Split(acceptHeader[0], ",")
		for i, v := range acceptHeader {
			acceptHeader[i] = strings.TrimSpace(v)
		}
	}
	if !slices.Contains(acceptHeader, jsonContentType) || !slices.Contains(acceptHeader, eventStreamContentType) {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Accept header must contain application/json and text/event-stream", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusNotAcceptable,
		)
		return
	}

	// check content-type header
	if contentType, present := r.Header["Content-Type"]; !present {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Content-Type header must be provided", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusNotAcceptable,
		)
		return
	} else if !slices.Contains(contentType, jsonContentType) {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Content-Type must be application/json", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusUnsupportedMediaType,
		)
		return
	}

	// read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to read request body", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	}
	defer r.Body.Close()

	// try to parse JSON
	if len(body) == 0 {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Empty JSON-RPC message", jsonrpc.ERROR_PARSE, nil, nil),
			http.StatusBadRequest,
		)
		return
	}

	// analyze raw message
	switch body[0] {
	case '{': // we have a single RPC-message
		rawMessage := jsonrpc.RawMessage{}
		if err := json.Unmarshal(body, &rawMessage); err != nil {
			s.writeJsonError(
				w,
				jsonrpc.GetErrorResponse("Failed to parse JSON-RPC message", jsonrpc.ERROR_PARSE, nil, nil),
				http.StatusBadRequest,
			)
			return
		}
		// basic validation of a raw message
		messageType, err := rawMessage.Validate()
		if err != nil {
			log.Errorf("Invalid JSON-RPC message %v : %v", rawMessage, err)
			s.writeJsonError(
				w,
				jsonrpc.GetErrorResponse("Invalid JSON-RPC message", jsonrpc.ERROR_PARSE, nil, nil),
				http.StatusBadRequest,
			)
			return
		}
		// process RPC-message
		switch messageType {
		case jsonrpc.MSG_TYPE_REQUEST:
			switch *rawMessage.Method {
			case mpcMethodInitialize:
				s.processInitializeRequest(w, r, body)
			case mpcMethodPing:
				s.processPingRequest(w, r, body)
			default:
				// process a single RPC message (we expect an initialized session)
				if session := s.validateSession(w, r); session != nil {
					defer session.CleanUp()
					s.processSingleRequest(w, r, session, body)
				}
			}
			return
		case jsonrpc.MSG_TYPE_RESPONSE:
			if session := s.validateSession(w, r); session != nil {
				defer session.CleanUp()
				s.processSingleResponse(w, r, session, body)
			}
			return
		case jsonrpc.MSG_TYPE_NOTIFY:
			if *rawMessage.Method == mpcMethodInitialized {
				s.processClientInitializedRequest(w, r)
			} else if session := s.validateSession(w, r); session != nil {
				defer session.CleanUp()
				s.processSingleNotification(w, r, session, body)
			}
			return
		default:
			s.writeJsonError(
				w,
				jsonrpc.GetErrorResponse("Invalid JSON-RPC message, unknown message type", jsonrpc.ERROR_PARSE, nil, nil),
				http.StatusBadRequest,
			)
			return
		}
	case '[': // we have a batch of RPC-messages
		// for batch, we expect an initialized session
		if session := s.validateSession(w, r); session != nil {
			defer session.CleanUp()
			s.processBatchRequest(w, r, session, body)
			return
		}
	default:
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Invalid JSON-RPC message", jsonrpc.ERROR_PARSE, nil, nil),
			http.StatusBadRequest,
		)
	}
}

func (s *StreamableServer) processPingRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	// parse payload for pingRequest
	pingRequest := jsonrpc.Request{}
	if err := json.Unmarshal(body, &pingRequest); err != nil {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to parse ping-request", jsonrpc.ERROR_PARSE, nil, nil),
			http.StatusBadRequest,
		)
		return
	}

	// check if the mpc-session-id header is present and update the session's last-ping-time
	if sessionId := r.Header.Get(mcpSessionIdHeader); sessionId != "" {
		if err := s.sessions.UpdateLastSeen(sessionId); err != nil { // check if the session is in the storage
			log.Errorf("Could not update last seen for a session with Id='%s': %v", sessionId, err)
		}
		w.Header().Set(mcpSessionIdHeader, sessionId)
	}

	// prepare and send ping-response
	pingResponse := jsonrpc.Response{
		JsonRpc: jsonrpc.JsonRpcVersion,
		Id:      pingRequest.Id,
		Result:  &struct{}{},
	}

	respBody, err := json.Marshal(pingResponse)
	if err != nil {
		log.Errorf("Failed to marshal ping-reply: %v", err)
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to marshal ping-reply", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	}

	// send ping-reply
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintln(w, string(respBody)); err != nil {
		log.Errorf("Failed to write ping-reply: %v", err)
	}
}

func (s *StreamableServer) processInitializeRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	// check if the mpc-session-id header is present
	if _, present := r.Header[mcpSessionIdHeader]; present {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse(
				"Mcp-Session-Id header must not be provided for initialize-request",
				jsonrpc.ERROR_INVALID_REQUEST, nil, nil),
			http.StatusBadRequest,
		)
		return
	}

	// parse payload for initialize-request
	initializeRequest := InitializeRequest{}
	if err := json.Unmarshal(body, &initializeRequest); err != nil {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to parse initialize-request", jsonrpc.ERROR_PARSE, nil, nil),
			http.StatusBadRequest,
		)
		return
	}

	// create a session
	sessionId := utils.NewSessionId()
	if _, err := s.sessions.CreateSession(sessionId, initializeRequest.Params.ClientInfo.Name, initializeRequest.Params.ClientInfo.Version); err != nil {
		log.Errorf("Failed to create a session: %v", err)
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to create a session", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	}

	// prepare initialize-reply
	initializeResponse := InitializeResponse{
		JsonRpc: jsonrpc.JsonRpcVersion,
		Id:      initializeRequest.Id,
		Result: &initializeResult{
			ProtocolVersion: mcpVersion,
			ServerInfo: &serverInfo{
				Name:    ServerName,
				Version: ServerVersion,
			},
			Capabilities: &serverCapabilities{},
		},
	}

	// populate capabilities
	if s.conf.Mcp.LoggingCapability {
		initializeResponse.Result.Capabilities.Logging = &struct{}{}
	}
	if len(s.conf.Mcp.Prompts) > 0 {
		initializeResponse.Result.Capabilities.Prompts = &serverCap{
			ListChanged: true,
		}
	}
	if len(s.conf.Mcp.Resources) > 0 {
		subscribe := false
		initializeResponse.Result.Capabilities.Resources = &serverCap{
			ListChanged: true,
			Subscribe:   &subscribe,
		}
	}
	if len(s.conf.Mcp.Tools) > 0 {
		initializeResponse.Result.Capabilities.Tools = &serverCap{
			ListChanged: true,
		}
	}

	respBody, err := json.Marshal(initializeResponse)
	if err != nil {
		log.Errorf("Failed to marshal initialize-reply: %v", err)
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to marshal initialize-reply", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	}

	// we have a good session now, so add mcp-session-id header
	w.Header().Set(mcpSessionIdHeader, sessionId)

	// send initialize-reply
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintln(w, string(respBody)); err != nil {
		log.Errorf("Failed to write initialize-reply: %v", err)
	}
}

func (s *StreamableServer) processClientInitializedRequest(w http.ResponseWriter, r *http.Request) {
	// check if the mpc-session-id header is present and initialize this session
	sessionId := r.Header.Get(mcpSessionIdHeader)
	if sessionId == "" {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse(
				"Mcp-Session-Id header must be provided for initialized-request",
				jsonrpc.ERROR_INVALID_REQUEST, nil, nil,
			),
			http.StatusBadRequest,
		)
		return
	} else if err := s.sessions.Initialize(sessionId); err != nil {
		log.Errorf("Failed to initialize a session with id='%s': %v", sessionId, err)
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to initialize a session", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	}

	// add mcp-session-id header
	w.Header().Set(mcpSessionIdHeader, sessionId)
	w.WriteHeader(http.StatusAccepted)
}

func (s *StreamableServer) processSingleResponse(w http.ResponseWriter, r *http.Request, session *sessions.Session, body []byte) {
	// TODO: parse and record response

	// add mcp-session-id header
	w.Header().Set(mcpSessionIdHeader, session.Id)
	w.WriteHeader(http.StatusAccepted)
}

func (s *StreamableServer) processSingleNotification(w http.ResponseWriter, r *http.Request, session *sessions.Session, body []byte) {
	// assume a server has notifications' handlers all set up
	result := s.mcpServer.HandleMessage(r.Context(), body)
	if result != nil {
		log.Errorf("Most likely failed to handle a notification %s with result: %v", string(body), result)
	}

	// add mcp-session-id header
	w.Header().Set(mcpSessionIdHeader, session.Id)
	w.WriteHeader(http.StatusAccepted)
}

func (s *StreamableServer) processSingleRequest(w http.ResponseWriter, r *http.Request, session *sessions.Session, body []byte) {
	// handle simple JSON reply when server configured for no streaming
	if s.conf.DisableStreaming {
		result := s.mcpServer.HandleMessage(r.Context(), body)
		s.sendNoStreamResponse(w, result, session)
		return
	}

	// streaming is enabled so open stream and process
	stream, err := s.streams.CreateStream(session.Id, s.conf.StreamBufferSize)
	if err != nil {
		log.Errorf("Failed to create a stream for a session %s : %v", session.Id, err)
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to create a stream for a session", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	}

	var ctx context.Context
	if s.conf.DisableStreamResume {
		ctx = r.Context()
	} else {
		ctx = context.Background() // for resumable streams, we use context detouched from the HTTP-request context
		if tok := r.Context().Value(mcpbustypes.TokenKey{}); tok != nil {
			ctx = context.WithValue(ctx, mcpbustypes.TokenKey{}, tok)
		}
		if integrationTok := r.Context().Value(mcpbustypes.IntegrationTokenKey{}); integrationTok != nil {
			ctx = context.WithValue(ctx, mcpbustypes.IntegrationTokenKey{}, integrationTok)
		}
	}

	// process a single message
	go s.processSingle(ctx, session, body, stream)

	// open SSE stream to send events to the client from the stream
	s.openSSEStream(w, r, stream, session)
}

func (s *StreamableServer) processBatchRequest(w http.ResponseWriter, r *http.Request, session *sessions.Session, body []byte) {
	rawBatch := []json.RawMessage{}
	if err := json.Unmarshal(body, &rawBatch); err != nil {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to parse batch-request", jsonrpc.ERROR_PARSE, nil, nil),
			http.StatusBadRequest,
		)
		return
	}

	// process in background if batch doesn't have requests and reply with 202
	if hasRequests, err := s.batchHasRequests(rawBatch); err != nil {
		log.Errorf("Failed to parse batch-request: %v", err)
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to parse batch-request", jsonrpc.ERROR_PARSE, nil, nil),
			http.StatusBadRequest,
		)
		return
	} else if !hasRequests {
		// batch contains only notifications and responses, start processing in the background
		go s.processBatchOfRepliesAndNotifications(rawBatch)
		// add mcp-session-id header
		w.Header().Set(mcpSessionIdHeader, session.Id)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// handle simple JSON reply when server configured for no streaming
	if s.conf.DisableStreaming {
		batchResult := make([]any, 0, len(rawBatch))
		for _, rawMessage := range rawBatch {
			batchResult = append(batchResult, s.mcpServer.HandleMessage(r.Context(), rawMessage))
		}
		s.sendNoStreamResponse(w, batchResult, session)
		return
	}

	// streaming is enabled so open stream and process a batch
	stream, err := s.streams.CreateStream(session.Id, s.conf.StreamBufferSize)
	if err != nil {
		log.Errorf("Failed to create a stream for a session %s : %v", session.Id, err)
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to create a stream for a session", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	}

	var ctx context.Context
	if s.conf.DisableStreamResume {
		ctx = r.Context()
	} else {
		ctx = context.Background() // for resumable streams, we use context detouched from the HTTP-request context
		if tok := r.Context().Value(mcpbustypes.TokenKey{}); tok != nil {
			ctx = context.WithValue(ctx, mcpbustypes.TokenKey{}, tok)
		}
		if integrationTok := r.Context().Value(mcpbustypes.IntegrationTokenKey{}); integrationTok != nil {
			ctx = context.WithValue(ctx, mcpbustypes.IntegrationTokenKey{}, integrationTok)
		}
	}

	// process batch
	go s.processBatch(ctx, session, rawBatch, stream)

	// open SSE stream to send events to the client from the stream
	s.openSSEStream(w, r, stream, session)
}

func (s *StreamableServer) batchHasRequests(rawBatch []json.RawMessage) (bool, error) {
	for _, rawMessage := range rawBatch {
		var msg jsonrpc.RawMessage
		if err := json.Unmarshal(rawMessage, &msg); err != nil {
			return false, err
		}
		if msgType, err := msg.Validate(); err != nil {
			return false, err
		} else if msgType == jsonrpc.MSG_TYPE_REQUEST {
			return true, nil
		}
	}
	return false, nil
}

func (s *StreamableServer) processBatchOfRepliesAndNotifications(rawBatch []json.RawMessage) {
	for _, rawMessage := range rawBatch {
		if res := s.mcpServer.HandleMessage(context.Background(), rawMessage); res != nil {
			log.Errorf("Most likely error when processing reply or notification: %v", res)
		}
	}
}

func (s *StreamableServer) sendNoStreamResponse(w http.ResponseWriter, resp any, session *sessions.Session) {
	response, err := json.Marshal(resp)
	if err != nil {
		log.Errorf("Failed to marshal a no-streaming reply: %v", err)
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to marshal a no-streaming reply", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	}
	w.Header().Set(mcpSessionIdHeader, session.Id)
	w.Header().Set("Content-Type", jsonContentType)
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintln(w, string(response)); err != nil {
		log.Errorf("Failed to write batch-reply: %v", err)
	}
}

func (s *StreamableServer) processSingle(ctx context.Context, session *sessions.Session, rawMessage json.RawMessage, outPutStream *Stream) {
	s.processBatch(ctx, session, []json.RawMessage{rawMessage}, outPutStream)
}

func (s *StreamableServer) processBatch(ctx context.Context, session *sessions.Session, batch []json.RawMessage, outPutStream *Stream) {
	isResumable := outPutStream.Type == STREAM_TYPE_REGULAR && s.isReplayOn()

	// close a channel to stop SSE stream when we are done
	defer outPutStream.Close()

	// single message requests might lead to notifications being sent before sending final reply from a tool
	// create channel for these notifications
	notificationChan := make(chan any)
	defer close(notificationChan)

	// add a notification channel to the context in case tool's implementation needs it
	ctxForTool := context.WithValue(ctx, "notificationChan", notificationChan)

	// add session to the context in case tool's implementation needs it
	ctxForTool = context.WithValue(ctxForTool, "session", session)

	// start handling a message
	resChan := make(chan any, s.conf.StreamBufferSize)
	go func(ch chan any, b []json.RawMessage) {
		defer close(ch)
		for _, rawMessage := range b {
			ch <- s.mcpServer.HandleMessage(ctxForTool, rawMessage)
		}
	}(resChan, batch)

	stopSending := false
	for {
		select {
		case <-ctx.Done():
			log.WithFields(log.Fields{
				"error":      ctx.Err(),
				"session_id": session.Id,
				"stream_id":  outPutStream.Id,
			}).Error("Client request context cancelled")
			if isResumable {
				stopSending = true
			} else {
				return
			}
		case <-session.Done():
			log.WithFields(log.Fields{
				"session_id": session.Id,
				"stream_id":  outPutStream.Id,
			}).Error("Session was cancelled")
			return
		case notifMessage := <-notificationChan:
			eventId := ""
			if !stopSending {
				log.Info("Sending notification to SSE")
				err := outPutStream.SendMessage(&Message{
					EventId: eventId,
					Data:    notifMessage,
				})
				if err != nil {
					log.WithError(err).Error("Failed to send message to a client")
				}
			} else if isResumable {
				log.Info("Recording message from notification channel")
				var err error
				eventId, err = s.events.RecordEvent(session.Id, outPutStream.Id, notifMessage)
				if err != nil {
					log.WithError(err).Error("Failed to record event")
				}
			}
		case res, ok := <-resChan:
			if !ok {
				log.WithFields(log.Fields{
					"session_id":      session.Id,
					"stream_id":       outPutStream.Id,
					"num_of_messages": len(batch),
				}).Info("Messages processed")
				return
			}
			eventId := ""
			if !stopSending {
				log.Info("Sending message to SSE")
				err := outPutStream.SendMessage(&Message{
					EventId: eventId,
					Data:    res,
				})
				if err != nil {
					log.WithError(err).Error("Failed to send message to stream")
				}
			} else if isResumable {
				log.Info("Recording message from resumable channel")
				var err error
				eventId, err = s.events.RecordEvent(session.Id, outPutStream.Id, res)
				if err != nil {
					log.WithError(err).Error("Failed to record event")
				}
			}
		default:
			log.Info("Still waiting for batch item processing")
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func (s *StreamableServer) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	// Accept header must include text/event-stream
	if acceptHeader, present := r.Header["Accept"]; !present {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Accept header must be provided", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusNotAcceptable,
		)
		return
	} else if !slices.Contains(acceptHeader, eventStreamContentType) {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Accept header must contain text/event-stream", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusNotAcceptable,
		)
		return
	}

	// get and validate a session
	session := s.validateSession(w, r)
	if session == nil {
		return
	}
	defer session.CleanUp()

	// add mcp-session-id header
	w.Header().Set(mcpSessionIdHeader, session.Id)

	// check if a client wants to resume the stream of events (then it is not a request to open a standalone stream)
	if lastEventId := r.Header.Get(lastEventIdHeader); lastEventId != "" {
		if s.isReplayOn() {
			s.resumeStream(w, r, lastEventId, session)
		}
		return
	}

	// check if a standalone stream is already open for the session
	// TODO: implement this as attribute of the session
	if stream, err := s.streams.GetStandaloneStream(session.Id); err != nil && !errors.Is(err, ErrStandaloneStreamNotFound) {
		log.Errorf("Failed to get a SSE standalone stream: %v", err)
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to get a SSE standalone stream", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	} else if stream != nil {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse(
				"Standalone SSE stream is already open. Only one standalone SSE stream is allowed per session",
				jsonrpc.ERROR_SERVER,
				nil,
				nil,
			),
			http.StatusConflict,
		)
		return
	}

	// create a new SSE stream for the session
	standaloneStream, err := s.streams.CreateStandaloneStream(session.Id, s.conf.StreamBufferSize)
	if err != nil {
		log.Errorf("Failed to create a SSE standalone stream: %v", err)
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to create a SSE standalone stream", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	}

	// start a pinger over stand-alone stream to keep the session alive
	if s.conf.KeepAlivePing {
		go s.startPinger(r.Context(), standaloneStream, session)
	}

	// start server request/notification notifier over a stand-alone stream
	go s.startServerNotifier(r.Context(), standaloneStream, session)

	// open a standalone SSE stream for the session
	s.openSSEStream(w, r, standaloneStream, session)
}

func (s *StreamableServer) shutdownSession(session *sessions.Session) {
	if err := s.sessions.DeleteSession(session.Id); err != nil {
		log.Errorf("Failed to delete a session %s : %v", session.Id, err)
	}

	if err := s.streams.DeleteStaleStreams(session.Id); err != nil {
		log.Errorf("Failed to delete stale streams for a session %s : %v", session.Id, err)
	}
}

func (s *StreamableServer) startPinger(ctx context.Context, stream *Stream, session *sessions.Session) {
	ticker := time.NewTicker(5 * time.Second) // Sends a ping every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Client disconnected, shutting down pinger")
			return
		case <-session.Done():
			log.Info("Session shutdown, shutting down pinger")
			return
		case <-ticker.C:
			log.Info("Sending ping to keep the stream alive")
			pingReq := &jsonrpc.Request{
				JsonRpc: jsonrpc.JsonRpcVersion,
				Id:      utils.NewMessageId(),
				Method:  mpcMethodPing,
			}
			if err := stream.SendMessage(&Message{
				EventId: "",
				Data:    pingReq,
			}); err != nil {
				log.Errorf("Failed to send a ping to a client: %v", err)
			}
		}
	}
}

func (s *StreamableServer) startServerNotifier(ctx context.Context, stream *Stream, session *sessions.Session) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Client disconnected, shutting down server notifier")
			return
		case <-session.Done():
			log.Info("Session shutdown, shutting down server notifier")
			return
		case <-ticker.C: // TODO: replace this with actual channel with requests or notifications
			log.Info("Sending server notification")
			pingReq := &jsonrpc.Request{
				JsonRpc: jsonrpc.JsonRpcVersion,
				Method:  "test_notification",
			}
			if err := stream.SendMessage(&Message{
				EventId: "",
				Data:    pingReq,
			}); err != nil {
				log.Errorf("Failed to send a ping to a client: %v", err)
			}
		}
	}
}

func (s *StreamableServer) handleDeleteRequest(w http.ResponseWriter, r *http.Request) {
	// check if the passed session is valid
	session := s.validateSession(w, r)
	if session == nil {
		return
	}
	defer session.CleanUp()

	// clean up the session and all the streams associated with it
	s.shutdownSession(session)

	w.WriteHeader(http.StatusOK)
}

func (s *StreamableServer) handleUnsupportedRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "POST, GET, DELETE")
	s.writeJsonError(
		w,
		jsonrpc.GetErrorResponse("Method not allowed", jsonrpc.ERROR_SERVER, nil, nil),
		http.StatusMethodNotAllowed,
	)
}

func (s *StreamableServer) writeJsonError(w http.ResponseWriter, response *jsonrpc.Response, httpCode int) {
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(httpCode)
	responseJson, _ := json.Marshal(response)
	if _, err := fmt.Fprintln(w, string(responseJson)); err != nil {
		log.Errorf("Failed to write error response: %v", err)
	}
}

func (s *StreamableServer) validateSession(w http.ResponseWriter, r *http.Request) *sessions.Session {
	if sessionId, present := r.Header[mcpSessionIdHeader]; !present { // check if the mpc-session-id header is present
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Mcp-Session-Id header must be provided", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusBadRequest,
		)
		return nil
	} else if len(sessionId) > 1 { // check if the mpc-session-id has one value
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Mcp-Session-Id header must contain one value", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusBadRequest,
		)
		return nil
	} else if session, err := s.sessions.GetSession(sessionId[0]); err != nil { // check if the session is in the storage
		log.Errorf("Could not find a session with Id='%s': %v", sessionId[0], err)
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Session not found", jsonrpc.ERROR_NOT_FOUND, nil, nil),
			http.StatusNotFound,
		)
		return nil
	} else if !session.Initialized { // check if the session is initialized
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse(
				"Session is not initialized, notifications/initialized is expected",
				jsonrpc.ERROR_SERVER, nil, nil,
			),
			http.StatusBadRequest,
		)
		return nil
	} else {
		return session
	}
}

func (s *StreamableServer) resumeStream(w http.ResponseWriter, r *http.Request, lastEventId string, session *sessions.Session) {
	streamId, eventId, err := utils.ParseEventId(lastEventId)
	if err != nil {
		log.WithError(err).Error("Failed to parse Last-Event-Id header value")
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Invalid Last-Event-Id header value", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusBadRequest,
		)
		return
	}

	eventsToReplay, err := s.events.GetEvents(session.Id, streamId, eventId)
	if err != nil {
		log.WithError(err).Error("Failed to get events")
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to get events", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	}

	stream, err := s.streams.CreateReplayStream(session.Id, streamId, s.conf.StreamBufferSize)
	if err != nil {
		log.WithError(err).Error("Failed to create a replay stream")
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse("Failed to create a replay stream", jsonrpc.ERROR_SERVER, nil, nil),
			http.StatusInternalServerError,
		)
		return
	}

	// start replaying stream
	go s.replayEvents(stream, eventsToReplay)

	// open SSE to send a replay stream
	s.openSSEStream(w, r, stream, session)
}

func (s *StreamableServer) replayEvents(replayStream *Stream, replayEvents []events.Event) {
	defer replayStream.Close()
	for _, event := range replayEvents {
		err := replayStream.SendMessage(&Message{
			EventId: replayStream.Id + event.ID, // we need to recreate event ID with the stream ID in it
			Data:    event.Data,
		})
		if err != nil {
			log.WithError(err).Error("Failed to send a replay event")
		}
	}
}

func (s *StreamableServer) deleteStream(stream *Stream) {
	if err := s.streams.DeleteStream(stream); err != nil {
		log.Errorf("Failed to delete a stream %s : %v", stream.Id, err)
	}
}

func (s *StreamableServer) openSSEStream(w http.ResponseWriter, r *http.Request, stream *Stream, session *sessions.Session) {
	// delete a stream no matter what happens if it is a standalone stream or resume is not enabled
	isResumable := stream.Type == STREAM_TYPE_REGULAR && s.isReplayOn()
	if !isResumable {
		defer s.deleteStream(stream)
	}

	// check if the server supports SSE
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeJsonError(
			w,
			jsonrpc.GetErrorResponse(
				"Failed to open a SSE standalone stream. SSE not supported",
				jsonrpc.ERROR_SERVER,
				nil,
				nil),
			http.StatusInternalServerError,
		)
		return
	}

	// send headers for SSE stream
	w.Header().Set("Content-Type", eventStreamContentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush() // flush the headers so that the client can start receiving events

	// start steaming events to the client
	for {
		select {
		case <-r.Context().Done():
			return
		case <-session.Done():
			if isResumable { // regular streams are deleted when the last message is received or the session is closed
				if err := s.streams.DeleteStream(stream); err != nil {
					log.Errorf("Failed to delete a stream %s : %v", stream.Id, err)
				}
			}
			return
		case message, ok := <-stream.Messages():
			if !ok { // the channel was closed, no more messages
				if isResumable { // regular streams are deleted when the last message is received or the session is closed
					if err := s.streams.DeleteStream(stream); err != nil {
						log.Errorf("Failed to delete a stream %s : %v", stream.Id, err)
					}
				}
				return
			}
			// check if a message contains already serialized JSON (e.g., from resumed stream)
			jsonMessage, ok := message.Data.(string)
			if !ok {
				// marshal to JSON
				jsonData, err := json.Marshal(message.Data)
				if err != nil {
					log.Errorf("Failed to marshal message %v: %v", message, err)
					continue
				}
				jsonMessage = string(jsonData)
			}
			eventId := ""
			if isResumable {
				eventId = message.EventId
			}
			if err := s.writeSSEEvent(w, jsonMessage, eventId); err != nil {
				log.Errorf("Failed to write an SSE event from %s stream: %v", stream.Type, err)
				continue
			} else {
				flusher.Flush()
			}
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func (s *StreamableServer) writeSSEEvent(w http.ResponseWriter, message string, eventId string) error {
	eventData := "event: message\n"
	if eventId != "" {
		eventData += fmt.Sprintf("id: %s\n", eventId)
	}
	eventData += fmt.Sprintf("data: %s\n\n", message)
	if _, err := fmt.Fprint(w, eventData); err != nil {
		return err
	}
	return nil
}

func (s *StreamableServer) isStreamingOn() bool {
	return s.streams != nil && !s.conf.DisableStreaming
}

func (s *StreamableServer) isReplayOn() bool {
	return s.streams != nil && !s.conf.DisableStreaming && !s.conf.DisableStreamResume
}
