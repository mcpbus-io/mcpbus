package auth

import (
	"errors"
	"sync"
	"time"
)

type InMemoryAuthStorage struct {
	clients         map[string]*RegisterResponse
	clientsMutex    sync.RWMutex
	oAuthFlows      map[string]*OauthFlow
	oauthFlowsMutex sync.RWMutex
	authTokens      map[string]*AuthToken
	authTokensMutex sync.RWMutex
}

func NewInMemoryAuthStorage() *InMemoryAuthStorage {
	return &InMemoryAuthStorage{
		clients:    make(map[string]*RegisterResponse),
		oAuthFlows: make(map[string]*OauthFlow),
		authTokens: make(map[string]*AuthToken),
	}
}

func (ks *InMemoryAuthStorage) AddClient(client *RegisterResponse) error {
	ks.clientsMutex.Lock()
	defer ks.clientsMutex.Unlock()
	ks.clients[client.ClientID] = client
	return nil
}

func (ks *InMemoryAuthStorage) GetClient(clientID string) (*RegisterResponse, error) {
	ks.clientsMutex.RLock()
	defer ks.clientsMutex.RUnlock()
	client, ok := ks.clients[clientID]
	if !ok {
		return nil, errors.New("client not found")
	}
	return client, nil
}

func (ks *InMemoryAuthStorage) DeleteClient(clientID string) {
	ks.clientsMutex.Lock()
	defer ks.clientsMutex.Unlock()
	delete(ks.clients, clientID)
}

func (ks *InMemoryAuthStorage) AddOAuthFlow(oauthFlow *OauthFlow) error {
	ks.oauthFlowsMutex.Lock()
	defer ks.oauthFlowsMutex.Unlock()
	ks.oAuthFlows[oauthFlow.RegisteredClient.ClientID] = oauthFlow
	return nil
}

func (ks *InMemoryAuthStorage) AddOAuthFlowByCode(code string, oauthFlow *OauthFlow) error {
	ks.oauthFlowsMutex.Lock()
	defer ks.oauthFlowsMutex.Unlock()
	ks.oAuthFlows[code] = oauthFlow
	return nil
}

func (ks *InMemoryAuthStorage) GetOAuthFlow(code string) (*OauthFlow, error) {
	ks.oauthFlowsMutex.RLock()
	defer ks.oauthFlowsMutex.RUnlock()
	oauthFlow, ok := ks.oAuthFlows[code]
	if !ok {
		return nil, errors.New("client flow not found")
	}
	return oauthFlow, nil
}

func (ks *InMemoryAuthStorage) DeleteOAuthFlow(code string) {
	ks.oauthFlowsMutex.Lock()
	defer ks.oauthFlowsMutex.Unlock()
	delete(ks.oAuthFlows, code)
}

func (ks *InMemoryAuthStorage) UpdateOAuthFlow(oauthFlow *OauthFlow) error {
	ks.oauthFlowsMutex.Lock()
	defer ks.oauthFlowsMutex.Unlock()
	ks.oAuthFlows[oauthFlow.AuthCode] = oauthFlow
	ks.oAuthFlows[oauthFlow.RegisteredClient.ClientID] = oauthFlow
	return nil
}

func (ks *InMemoryAuthStorage) AddAuthToken(oauthToken *AuthToken) error {
	ks.authTokensMutex.Lock()
	defer ks.authTokensMutex.Unlock()
	ks.authTokens[oauthToken.AccessToken] = oauthToken
	ks.authTokens[oauthToken.RefreshToken] = oauthToken
	return nil
}

func (ks *InMemoryAuthStorage) GetAuthToken(token string) (*AuthToken, error) {
	ks.authTokensMutex.RLock()
	defer ks.authTokensMutex.RUnlock()
	authToken, ok := ks.authTokens[token]
	if !ok {
		return nil, errors.New("access token not found")
	}
	if authToken.IssuedAt.Add(time.Second * time.Duration(authToken.ExpiresIn)).Before(time.Now()) {
		return nil, errors.New("access token is expired")
	}
	return authToken, nil
}

func (ks *InMemoryAuthStorage) GetRefreshToken(refreshToken string) (*AuthToken, error) {
	ks.authTokensMutex.RLock()
	defer ks.authTokensMutex.RUnlock()
	authToken, ok := ks.authTokens[refreshToken]
	if !ok {
		return nil, errors.New("refresh token not found")
	}
	return authToken, nil
}

func (ks *InMemoryAuthStorage) DeleteAuthToken(token string) {
	ks.authTokensMutex.Lock()
	defer ks.authTokensMutex.Unlock()
	authToken, ok := ks.authTokens[token]
	if !ok {
		return
	}
	delete(ks.authTokens, token)
	delete(ks.authTokens, authToken.RefreshToken)
}

func (ks *InMemoryAuthStorage) RefreshToken(refreshToken string, newToken *AuthToken) error {
	ks.authTokensMutex.Lock()
	defer ks.authTokensMutex.Unlock()
	if authToken, ok := ks.authTokens[refreshToken]; ok {
		delete(ks.authTokens, refreshToken)
		delete(ks.authTokens, authToken.AccessToken)
	}
	ks.authTokens[newToken.AccessToken] = newToken
	ks.authTokens[newToken.RefreshToken] = newToken
	return nil
}
