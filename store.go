package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

type InMemoryStore struct {
	sync.Mutex
	store map[string]string
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		store: make(map[string]string),
	}
}

// Set a key-value pair
func (s *InMemoryStore) Set(key string, value string) {
	s.Lock()
	defer s.Unlock()
	s.store[key] = value
}

// Get a value by key
func (s *InMemoryStore) Get(key string) (string, bool) {
	s.Lock()
	defer s.Unlock()
	value, ok := s.store[key]
	return value, ok
}

// Delete a key-value pair
func (s *InMemoryStore) Delete(key string) {
	s.Lock()
	defer s.Unlock()
	delete(s.store, key)
}

func (s *InMemoryStore) Drop() {
	s.Lock()
	defer s.Unlock()
	s.store = make(map[string]string)
}

type Response struct {
	Error string `json:"error,omitempty"`
	Data  any    `json:"data,omitempty"`
}

type StoredData struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func main() {
	s := NewInMemoryStore()
	apiKey := ""
	port := "9191"

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		providedAPIKey := r.Header.Get("X-API-KEY")
		if providedAPIKey != apiKey {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		// Fetch
		if r.Method == http.MethodGet {
			key := r.URL.Query().Get("key")
			value, ok := s.Get(key)
			resp := &Response{}
			if ok {
				resp.Data = value
				json.NewEncoder(w).Encode(resp)
				return
			}

			resp.Error = "missing"
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Update
		if r.Method == http.MethodPost {
			var b StoredData
			resp := &Response{}
			err := json.NewDecoder(r.Body).Decode(&b)
			if err != nil {
				log.Println("could not insert new key", err)
				resp.Error = "internalError"
				json.NewEncoder(w).Encode(resp)
				return
			}

			s.Set(b.Key, b.Value)
			resp.Data = b
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Delete
		if r.Method == http.MethodDelete {
			q := r.URL.Query()

			// Drop the whole store.
			drop := q.Get("drop")
			if drop == "true" {
				s.Drop()
				resp := &Response{
					Data: true,
				}
				json.NewEncoder(w).Encode(resp)
				return
			}

			// Delete by key.
			key := q.Get("key")
			s.Delete(key)
			resp := &Response{
				Data: true,
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

	})

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
