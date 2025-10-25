package cache

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	msg   *dns.Msg
	exp   time.Time
	stamp time.Time
	trace string
}

type Cache struct {
	mu    sync.RWMutex
	items map[string]*entry
}

func New() *Cache { return &Cache{items: make(map[string]*entry)} }

func keyFromMsg(q *dns.Msg) string {
	if len(q.Question) == 0 {
		return ""
	}
	qq := q.Question[0]
	return qq.Name + ":" + dns.TypeToString[qq.Qtype]
}

func ttlFromMsg(m *dns.Msg) time.Duration {
	min := uint32(0)
	set := false
	for _, rr := range m.Answer {
		if !set || rr.Header().Ttl < min {
			min = rr.Header().Ttl
			set = true
		}
	}
	if !set {
		return 0
	}
	return time.Duration(min) * time.Second
}

// GetWithTrace returns cached msg and its original trace id if not expired.
func (c *Cache) GetWithTrace(q *dns.Msg) (*dns.Msg, string) {
	k := keyFromMsg(q)
	if k == "" {
		return nil, ""
	}
	c.mu.RLock()
	e := c.items[k]
	c.mu.RUnlock()
	if e == nil {
		return nil, ""
	}
	if time.Now().After(e.exp) {
		return nil, ""
	}
	return e.msg.Copy(), e.trace
}

// SetWithTrace stores msg along with its originating trace id.
func (c *Cache) SetWithTrace(q *dns.Msg, m *dns.Msg, trace string) {
	k := keyFromMsg(q)
	if k == "" || m == nil {
		return
	}
	ttl := ttlFromMsg(m)
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.items[k] = &entry{msg: m.Copy(), exp: time.Now().Add(ttl), stamp: time.Now(), trace: trace}
	c.mu.Unlock()
}

// Legacy helpers kept for compatibility (unused in current server)
func (c *Cache) Get(q *dns.Msg, refresh func()) *dns.Msg {
	m, _ := c.GetWithTrace(q)
	return m
}

func (c *Cache) Set(q *dns.Msg, m *dns.Msg) {
	c.SetWithTrace(q, m, "")
}
