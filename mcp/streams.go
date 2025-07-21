package mcp

import (
	"errors"
	"github.com/mcpbus-io/mcpbus/utils"
	log "github.com/sirupsen/logrus"
	"sync"
)

const (
	STREAM_TYPE_REGULAR    = "regular"
	STREAM_TYPE_STANDALONE = "standalone"
)

type StreamsStorage struct {
	streams      map[string]*Stream
	streamsMutex sync.RWMutex
}

var (
	ErrStandaloneStreamNotFound = errors.New("standalone stream is not found")
)

func (s *StreamsStorage) CreateStandaloneStream(sessionId string, bufferSize uint) (*Stream, error) {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()

	if _, ok := s.streams[sessionId]; ok {
		return nil, errors.New("standalone stream is already present")
	}

	stream := &Stream{
		Id:        utils.NewStreamId(),
		Type:      STREAM_TYPE_STANDALONE,
		SessionId: sessionId,
		messages:  make(chan *Message, bufferSize),
		closed:    false,
	}

	s.streams[sessionId] = stream

	return stream, nil
}

func (s *StreamsStorage) GetStandaloneStream(sessionId string) (*Stream, error) {
	s.streamsMutex.RLock()
	defer s.streamsMutex.RUnlock()
	stream, ok := s.streams[sessionId]
	if !ok {
		return nil, ErrStandaloneStreamNotFound
	}

	return stream, nil
}

func NewStreamsStorage() *StreamsStorage {
	return &StreamsStorage{
		streams: make(map[string]*Stream),
	}
}

func (s *StreamsStorage) CreateStream(sessionId string, bufferSize uint) (*Stream, error) {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()

	id := utils.NewStreamId()

	stream := &Stream{
		Id:        id,
		Type:      STREAM_TYPE_REGULAR,
		SessionId: sessionId,
		messages:  make(chan *Message, bufferSize),
		closed:    false,
	}

	s.streams[sessionId+id] = stream

	return stream, nil
}

func (s *StreamsStorage) CreateReplayStream(sessionId string, streamId string, bufferSize uint) (*Stream, error) {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()

	stream := &Stream{
		Id:        streamId,
		Type:      STREAM_TYPE_REGULAR,
		SessionId: sessionId,
		messages:  make(chan *Message, bufferSize),
		closed:    false,
	}

	s.streams[sessionId+streamId] = stream

	return stream, nil
}

func (s *StreamsStorage) GetStream(sessionId string, streamId string) (*Stream, error) {
	s.streamsMutex.RLock()
	defer s.streamsMutex.RUnlock()
	stream, ok := s.streams[sessionId+streamId]
	if !ok {
		return nil, errors.New("stream is not found")
	}

	return stream, nil
}

func (s *StreamsStorage) DeleteStream(stream *Stream) error {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()

	stream.Close()

	if stream.Type == STREAM_TYPE_STANDALONE {
		delete(s.streams, stream.SessionId)
	} else {
		delete(s.streams, stream.SessionId+stream.Id)
	}

	return nil
}

func (s *StreamsStorage) DeleteStaleStreams(sessionId string) error {
	for _, stream := range s.streams {
		if stream.SessionId == sessionId {
			if err := s.DeleteStream(stream); err != nil {
				log.Error("could not delete stream %s: %v", stream.Id, err)
			}
		}
	}

	return nil
}

type Stream struct {
	Id        string `json:"id"`
	Type      string `json:"type"`
	SessionId string `json:"session_id"`
	messages  chan *Message
	closed    bool
}

type Message struct {
	EventId string `json:"event_id"`
	Data    any    `json:"data"`
}

func (s *Stream) Messages() <-chan *Message {
	return s.messages
}

func (s *Stream) SendMessage(message *Message) error {
	if s.closed {
		return errors.New("stream is closed")
	}
	s.messages <- message
	return nil
}

func (s *Stream) Close() {
	if s.closed {
		return
	}
	close(s.messages)
	s.closed = true
}
