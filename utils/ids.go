package utils

import (
	"errors"
	"github.com/google/uuid"
)

func ParseEventId(eventId string) (string, string, error) {
	if len(eventId) < 45 {
		return "", "", errors.New("Wrong eventId length: " + eventId)
	}

	return eventId[:32], eventId[32:], nil
}

func NewSessionId() string {
	return NewId()
}

func NewMessageId() string {
	return NewId()
}

func NewStreamId() string {
	return NewId()
}

func NewEventId(streamId string) string {
	return streamId + NewId()
}

func NewAuthToken() string {
	return NewId()
}

func NewAuthCode() string {
	return NewId()
}

func NewId() string {
	id := uuid.NewString()
	return id[:8] + id[9:13] + id[14:18] + id[19:23] + id[24:]
}
