package events

type Event struct {
	ID   string
	Data string
}

type Storage interface {
	RecordEvent(sessionId string, streamId string, message any) (string, error)
	GetEvents(sessionId string, streamId string, sinceEventId string) ([]Event, error)
}
