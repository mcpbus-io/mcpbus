package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"

	"github.com/mcpbus-io/mcpbus/utils"
)

const (
	Prefix     = "auth:"
	DefaultExp = 1 * time.Hour
)

type RedisStorage struct {
	rdb        *redis.Client
	expiration time.Duration
}

func NewRedisStorage(rdb *redis.Client, exp time.Duration) *RedisStorage {
	if exp == 0 {
		exp = DefaultExp
	}
	return &RedisStorage{
		rdb:        rdb,
		expiration: exp,
	}
}

func (r RedisStorage) AddClient(client *RegisterResponse) error {
	jsonData, err := json.Marshal(client)
	if err != nil {
		return err
	}

	expiration := r.getExpirationForClient(client)

	res := r.rdb.Set(context.Background(), r.getClientKey(client.ClientID), string(jsonData), expiration)
	if err := res.Err(); err != nil {
		return err
	}

	return nil
}

func (r RedisStorage) getExpirationForClient(client *RegisterResponse) time.Duration {
	if client.ClientSecretExpiresAt != 0 {
		return time.Unix(client.ClientSecretExpiresAt, 0).Sub(time.Now())
	}

	return 0
}

func (r RedisStorage) GetClient(clientID string) (*RegisterResponse, error) {
	res := r.rdb.Get(context.Background(), r.getClientKey(clientID))
	if err := res.Err(); err != nil {
		return nil, err
	}

	client := &RegisterResponse{}
	if err := json.Unmarshal([]byte(res.Val()), client); err != nil {
		return nil, err
	}

	return client, nil
}

func (r RedisStorage) DeleteClient(clientID string) {
	if err := r.rdb.Del(context.Background(), r.getClientKey(clientID)).Err(); err != nil {
		log.WithError(err).Warn("failed to delete oauth client")
	}
}

func (r RedisStorage) AddOAuthFlow(oauthFlow *OauthFlow) error {
	jsonData, err := json.Marshal(oauthFlow)
	if err != nil {
		return err
	}

	expiration := r.getExpirationForClient(oauthFlow.RegisteredClient)

	res := r.rdb.Set(context.Background(), r.getFlowKey(oauthFlow.RegisteredClient.ClientID), string(jsonData), expiration)
	if err := res.Err(); err != nil {
		return err
	}

	return nil
}

func (r RedisStorage) AddOAuthFlowByCode(code string, oauthFlow *OauthFlow) error {
	jsonData, err := json.Marshal(oauthFlow)
	if err != nil {
		return err
	}

	expiration := r.getExpirationForClient(oauthFlow.RegisteredClient)

	res := r.rdb.Set(context.Background(), r.getFlowKey(code), string(jsonData), expiration)
	if err := res.Err(); err != nil {
		return err
	}

	return nil
}

func (r RedisStorage) GetOAuthFlow(key string) (*OauthFlow, error) {
	res := r.rdb.Get(context.Background(), r.getFlowKey(key))
	if err := res.Err(); err != nil {
		return nil, err
	}

	flow := &OauthFlow{}
	if err := json.Unmarshal([]byte(res.Val()), flow); err != nil {
		return nil, err
	}

	return flow, nil
}

func (r RedisStorage) DeleteOAuthFlow(key string) {
	if err := r.rdb.Del(context.Background(), r.getFlowKey(key)).Err(); err != nil {
		log.WithError(err).Warn("failed to delete oauth flow")
	}
}

func (r RedisStorage) UpdateOAuthFlow(oauthFlow *OauthFlow) error {
	if err := r.AddOAuthFlowByCode(oauthFlow.AuthCode, oauthFlow); err != nil {
		return err
	}
	if err := r.AddOAuthFlow(oauthFlow); err != nil {
		return err
	}
	return nil
}

func (r RedisStorage) AddAuthToken(oauthToken *AuthToken) error {
	jsonData, err := json.Marshal(oauthToken)
	if err != nil {
		return err
	}

	expiration := time.Second * time.Duration(oauthToken.ExpiresIn)
	res := r.rdb.Set(context.Background(), r.getTokenKey(oauthToken.AccessToken), string(jsonData), expiration)
	if err := res.Err(); err != nil {
		return err
	}

	// refresh tokens will not expire as the associate client expires
	refreshExp := r.getExpirationForClient(oauthToken.Client)
	res = r.rdb.Set(context.Background(), r.getRefreshTokenKey(oauthToken.RefreshToken), string(jsonData), refreshExp)
	if err := res.Err(); err != nil {
		return err
	}

	return nil
}

func (r RedisStorage) GetAuthToken(key string) (*AuthToken, error) {
	res := r.rdb.Get(context.Background(), r.getTokenKey(key))
	if err := res.Err(); err != nil {
		return nil, err
	}

	oauthToken := &AuthToken{}
	if err := json.Unmarshal([]byte(res.Val()), oauthToken); err != nil {
		return nil, err
	}

	return oauthToken, nil
}

func (r RedisStorage) GetRefreshToken(refreshToken string) (*AuthToken, error) {
	res := r.rdb.Get(context.Background(), r.getRefreshTokenKey(refreshToken))
	if err := res.Err(); err != nil {
		return nil, err
	}

	oauthToken := &AuthToken{}
	if err := json.Unmarshal([]byte(res.Val()), oauthToken); err != nil {
		return nil, err
	}

	return oauthToken, nil
}

func (r RedisStorage) DeleteAuthToken(key string) {
	token, err := r.GetAuthToken(key)
	if err != nil {
		log.WithError(err).Error("failed to delete oauth token - not found")
		return
	} else if token != nil {
		if err := r.rdb.Del(context.Background(), r.getRefreshTokenKey(token.RefreshToken)).Err(); err != nil {
			log.WithError(err).Error("failed to delete refresh token")
		}
	}
	if err := r.rdb.Del(context.Background(), r.getTokenKey(key)).Err(); err != nil {
		log.WithError(err).Error("failed to delete oauth token")
	}
}

func (r RedisStorage) RefreshToken(refreshOldToken string, newToken *AuthToken) error {
	if refreshToken, err := r.GetRefreshToken(refreshOldToken); err == nil {
		if err := r.rdb.Del(context.Background(), r.getRefreshTokenKey(refreshOldToken)).Err(); err != nil {
			log.WithError(err).Error("failed to delete old refresh token")
		}
		if err := r.rdb.Del(context.Background(), r.getTokenKey(refreshToken.AccessToken)).Err(); err != nil {
			log.WithError(err).Error("failed to delete old auth token")
		}
	}

	if err := r.AddAuthToken(newToken); err != nil {
		return err
	}

	return nil
}

func (r RedisStorage) getClientKey(key string) string {
	return Prefix + "oauth-client:" + utils.SecureKey(key)
}

func (r RedisStorage) getFlowKey(key string) string {
	return Prefix + "oauth-flow:" + utils.SecureKey(key)
}

func (r RedisStorage) getTokenKey(key string) string {
	return Prefix + "oauth-token:" + utils.SecureKey(key)
}

func (r RedisStorage) getRefreshTokenKey(key string) string {
	return Prefix + "oauth-refresh-token:" + utils.SecureKey(key)
}
