package sessions

import log "github.com/sirupsen/logrus"

type SessionsStorage interface {
	GetSession(sessionId string) (*Session, error)
	UpdateLastSeen(sessionId string) error
	Initialize(sessionId string) error
	CreateSession(sessionId string, clientName string, clientVersion string) (*Session, error)
	DeleteSession(sessionId string) error
}

type Session struct {
	Id            string `json:"id"`
	LastSeen      int64  `json:"last_seen"`
	ClientName    string `json:"client_name"`
	ClientVersion string `json:"client_version"`
	Initialized   bool   `json:"initialized"`
	done          chan struct{}
	cleanUp       func() error
}

func (s *Session) Done() <-chan struct{} {
	return s.done
}

func (s *Session) CleanUp() error {
	if s.cleanUp != nil {
		log.Info("Session cleaning up")
		err := s.cleanUp()
		if err != nil {
			return err
		}
	}

	return nil
}
