package events

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/mcpbus-io/mcpbus/utils"
)

type InMemory struct {
	events       map[string][]Event
	eventIndexes map[string]int
	eventLock    sync.RWMutex
}

func NewInMemory() *InMemory {
	return &InMemory{
		events: make(map[string][]Event),
	}
}

func (i *InMemory) RecordEvent(sessionId string, streamId string, message any) (string, error) {
	i.eventLock.Lock()
	defer i.eventLock.Unlock()

	jsonData, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	eventId := utils.NewEventId(streamId)
	event := Event{
		ID:   eventId,
		Data: string(jsonData),
	}

	if eventsList, ok := i.events[sessionId+streamId]; !ok {
		i.events[sessionId+streamId] = []Event{event}
		i.eventIndexes[eventId] = 0
	} else {
		eventsList = append(eventsList, event)
		i.events[sessionId+streamId] = eventsList
		i.eventIndexes[eventId] = len(eventsList) - 1
	}

	return eventId, nil
}

func (i *InMemory) GetEvents(sessionId string, streamId string, sinceEventId string) ([]Event, error) {
	i.eventLock.RLock()
	defer i.eventLock.RUnlock()

	eventsList, ok := i.events[sessionId+streamId]
	if !ok {
		return nil, errors.New("event not found")
	}

	eventIndex, ok := i.eventIndexes[streamId+sinceEventId]
	if !ok {
		return nil, errors.New("event not found")
	}

	return eventsList[eventIndex:], nil
}
