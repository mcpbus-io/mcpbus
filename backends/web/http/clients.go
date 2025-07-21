package http

import (
	"net/http"
	"sync"
)

var HttpClientPool clientsPool

func init() {
	HttpClientPool = clientsPool{
		clients: make(map[string]*http.Client),
	}
}

type clientsPool struct {
	clients     map[string]*http.Client
	clientsLock sync.RWMutex
}

func (c *clientsPool) Get(name string) *http.Client {
	c.clientsLock.RLock()
	defer c.clientsLock.RUnlock()
	if client, ok := c.clients[name]; ok {
		return client
	}
	return nil
}

func (c *clientsPool) Set(host string, client *http.Client) {
	c.clientsLock.Lock()
	defer c.clientsLock.Unlock()
	c.clients[host] = client
}
