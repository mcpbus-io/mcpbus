package events

import (
	"context"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"net/url"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/mcpbus-io/mcpbus/utils"
)

const (
	Prefix     = "streams:"
	DefaultExp = 1 * time.Hour
)

type Redis struct {
	rdb        *redis.Client
	expiration time.Duration
}

func NewRedisStorage(rdb *redis.Client, exp time.Duration) *Redis {
	if exp == 0 {
		exp = DefaultExp
	}

	return &Redis{
		rdb:        rdb,
		expiration: exp,
	}
}

func (r *Redis) RecordEvent(sessionId string, streamId string, message any) (string, error) {
	jsonMessage, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	key := r.getStreamKey(sessionId, streamId)

	id, err := r.rdb.XAdd(context.Background(), &redis.XAddArgs{
		Stream: key,
		Values: map[string]string{
			"message": url.QueryEscape(string(jsonMessage)), // encode JSON so xadd will accept it as a string
		},
	}).Result()
	if err != nil {
		return "", err
	}

	// set/reset expiration on every event recorded
	go r.rdb.Expire(context.Background(), key, r.expiration)

	return streamId + id, nil
}

func (r *Redis) GetEvents(sessionId string, streamId string, sinceEventId string) ([]Event, error) {
	key := r.getStreamKey(sessionId, streamId)
	// TODO: change to read it by pages with iterator returned
	resMessages, err := r.rdb.XRange(context.Background(), key, sinceEventId, "+").Result()
	if err != nil {
		return nil, err
	}

	events := make([]Event, len(resMessages))
	for i, message := range resMessages {
		jsonMessage, ok := message.Values["message"].(string) // convert value to string
		if !ok {
			log.Warning("Failed to convert to string from redis stream message")
			continue
		}
		jsonMessage, err = url.QueryUnescape(jsonMessage) // decode back to normal JSON
		if err != nil {
			log.Warning("Failed to unescape message from redis stream message")
			continue
		}
		events[i] = Event{
			ID:   message.ID,
			Data: jsonMessage,
		}
	}

	return events, nil
}

func (r *Redis) getStreamKey(sessionId string, streamId string) string {
	return Prefix + utils.SecureKey(sessionId) + ":" + utils.SecureKey(streamId)
}
