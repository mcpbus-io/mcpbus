package sessions

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/mcpbus-io/mcpbus/utils"
)

const (
	Prefix     = "sessions:"
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

func (r RedisStorage) GetSession(sessionId string) (*Session, error) {
	session, err := r.getSession(sessionId)
	if err != nil {
		return nil, err
	}
	session.done = make(chan struct{})

	go r.UpdateLastSeen(sessionId)

	key := r.getKey(sessionId)
	pubSub := r.rdb.Subscribe(context.Background(), key)

	// cleanUp is called when the request is done, we need to unsubscribe when it happens
	session.cleanUp = pubSub.Close

	// we need to identify that session is deleted for the long-running operations
	go func(s *Session) {
		ch := pubSub.Channel()
		for {
			select {
			case <-ch:
				s.done <- struct{}{}
				return
			case <-time.After(r.expiration):
				s.done <- struct{}{}
				return
			default:
				time.Sleep(5 * time.Millisecond)
			}
		}
	}(session)

	return session, nil
}

func (r RedisStorage) UpdateLastSeen(sessionId string) error {
	key := r.getKey(sessionId)
	res := r.rdb.Expire(context.Background(), key, r.expiration)
	if err := res.Err(); err != nil {
		return err
	}
	return nil
}

func (r RedisStorage) Initialize(sessionId string) error {
	session, err := r.getSession(sessionId)
	if err != nil {
		return err
	}
	if session.Initialized {
		return ErrSessionAlreadyInitialized
	}

	session.Initialized = true
	jsonData, err := json.Marshal(session)
	if err != nil {
		return err
	}

	key := r.getKey(sessionId)

	res := r.rdb.Set(context.Background(), key, string(jsonData), r.expiration)
	if err := res.Err(); err != nil {
		return err
	}

	return nil
}

func (r RedisStorage) CreateSession(sessionId string, clientName string, clientVersion string) (*Session, error) {
	session := &Session{
		Id:            sessionId,
		ClientName:    clientName,
		ClientVersion: clientVersion,
		Initialized:   false,
		done:          make(chan struct{}),
	}
	jsonData, err := json.Marshal(session)
	if err != nil {
		return nil, err
	}

	key := r.getKey(sessionId)

	res := r.rdb.Set(context.Background(), key, string(jsonData), r.expiration)
	if err := res.Err(); err != nil {
		return nil, err
	}

	return session, nil
}

func (r RedisStorage) DeleteSession(sessionId string) error {
	key := r.getKey(sessionId)

	if err := r.rdb.Del(context.Background(), key).Err(); err != nil {
		return err
	}

	// let all active streams know that session is deleted so they can gracefully exit
	if err := r.rdb.Publish(context.Background(), key, "del session").Err(); err != nil {
		return err
	}

	return nil
}

func (r RedisStorage) getSession(sessionId string) (*Session, error) {
	key := r.getKey(sessionId)

	res := r.rdb.Get(context.Background(), key)
	if err := res.Err(); err != nil {
		return nil, err
	}

	session := &Session{}
	if err := json.Unmarshal([]byte(res.Val()), session); err != nil {
		return nil, err
	}

	return session, nil
}

func (r RedisStorage) getKey(sessionId string) string {
	return Prefix + utils.SecureKey(sessionId)
}
