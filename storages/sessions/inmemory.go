package sessions

import (
	"errors"
	"sync"
	"time"
)

type InMemorySessionsStorage struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

var (
	ErrSessionNotFound           = errors.New("session not found")
	ErrSessionAlreadyInitialized = errors.New("session already initialized")
)

func NewInMemorySessionsStorage() *InMemorySessionsStorage {
	return &InMemorySessionsStorage{
		sessions: make(map[string]*Session),
	}
}

func (s *InMemorySessionsStorage) GetSession(sessionId string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, exists := s.sessions[sessionId]
	if !exists {
		return nil, ErrSessionNotFound
	}
	return session, nil
}

func (s *InMemorySessionsStorage) UpdateLastSeen(sessionId string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, exists := s.sessions[sessionId]; exists {
		session.LastSeen = time.Now().Unix()
	} else {
		return ErrSessionNotFound
	}

	return nil
}

func (s *InMemorySessionsStorage) Initialize(sessionId string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, exists := s.sessions[sessionId]; exists {
		if session.Initialized {
			return ErrSessionAlreadyInitialized
		}
		session.Initialized = true
	} else {
		return ErrSessionNotFound
	}
	return nil
}

func (s *InMemorySessionsStorage) CreateSession(sessionId string, clientName string, clientVersion string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := &Session{
		Id:            sessionId,
		LastSeen:      time.Now().Unix(),
		ClientName:    clientName,
		ClientVersion: clientVersion,
		Initialized:   false,
		done:          make(chan struct{}),
	}
	s.sessions[sessionId] = session
	return session, nil
}

func (s *InMemorySessionsStorage) DeleteSession(sessionId string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, exists := s.sessions[sessionId]; !exists {
		return ErrSessionNotFound
	} else {
		close(session.done)
	}

	delete(s.sessions, sessionId)
	return nil
}
