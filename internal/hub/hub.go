// language: Go, file: internal/hub/hub.go
// A tiny fan-out broker. Every connected dashboard subscribes and receives
// JSON frames; slow consumers are dropped rather than allowed to stall the
// reconciler that publishes to them.
package hub

import (
	"encoding/json"
	"sync"
)

// Hub broadcasts messages to all current subscribers.
type Hub struct {
	mu      sync.RWMutex
	subs    map[int]chan []byte
	nextID  int
	dropped uint64
}

// New creates an empty hub.
func New() *Hub {
	return &Hub{subs: make(map[int]chan []byte)}
}

// Subscribe registers a subscriber and returns its channel plus a cancel func.
// The cancel func is idempotent and closes the channel.
func (h *Hub) Subscribe() (<-chan []byte, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.nextID
	h.nextID++
	// Buffer absorbs a burst of frames without blocking the publisher.
	ch := make(chan []byte, 32)
	h.subs[id] = ch

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			if c, ok := h.subs[id]; ok {
				delete(h.subs, id)
				close(c)
			}
		})
	}
	return ch, cancel
}

// Broadcast marshals v and publishes it to every subscriber.
func (h *Hub) Broadcast(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.Publish(b)
}

// Publish sends pre-marshalled bytes to every subscriber.
func (h *Hub) Publish(b []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ch := range h.subs {
		select {
		case ch <- b:
		default:
			// Subscriber is not draining. Dropping one frame keeps the rest of
			// the fleet live; the next full state frame re-syncs them anyway.
			h.dropped++
		}
	}
}

// Count returns the number of live subscribers.
func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}

// Dropped returns how many frames were discarded due to backpressure.
func (h *Hub) Dropped() uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.dropped
}
