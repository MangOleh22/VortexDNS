package cache

import (
	"hash/fnv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// CacheItem represents a single DNS answer in the cache
type CacheItem struct {
	Response    *dns.Msg
	ExpiresAt   time.Time
	OriginalTTL uint32
	Prefetching int32 // 0 = false, 1 = prefetch in progress
}

// CacheShard is a thread-safe partition of the DNS cache
type CacheShard struct {
	mu    sync.RWMutex
	items map[string]*CacheItem
}

// DNSCache implements a highly concurrent sharded DNS cache
type DNSCache struct {
	shards      [64]*CacheShard
	maxSize     int
	minTTL      time.Duration
	maxTTL      time.Duration
	prefetch    bool
	prefetchChan chan prefetchRequest
}

type prefetchRequest struct {
	Key    string
	Msg    *dns.Msg
	ResolveFn func(req *dns.Msg) (*dns.Msg, error)
}

// New creates a new DNSCache instance
func New(maxSize int, minTTLSeconds int, maxTTLSeconds int, prefetch bool) *DNSCache {
	c := &DNSCache{
		maxSize:      maxSize,
		minTTL:      time.Duration(minTTLSeconds) * time.Second,
		maxTTL:      time.Duration(maxTTLSeconds) * time.Second,
		prefetch:    prefetch,
		prefetchChan: make(chan prefetchRequest, 1000),
	}

	for i := 0; i < 64; i++ {
		c.shards[i] = &CacheShard{
			items: make(map[string]*CacheItem),
		}
	}

	if prefetch {
		go c.prefetchWorker()
	}

	return c
}

// getShardIndex calculates the shard index for a cache key using FNV-1a hash
func (c *DNSCache) getShardIndex(key string) uint8 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return uint8(h.Sum32() % 64)
}

// makeKey creates a unique string for a DNS question (Name + Type + Class)
func (c *DNSCache) makeKey(q dns.Question) string {
	return strings.ToLower(q.Name) + ":" + dns.TypeToString[q.Qtype] + ":" + dns.ClassToString[q.Qclass]
}

// Get retrieves a DNS response from the cache.
// If the item exists but is near expiration (remaining TTL < 10%), it schedules a prefetch.
func (c *DNSCache) Get(req *dns.Msg, resolveFn func(req *dns.Msg) (*dns.Msg, error)) (*dns.Msg, bool) {
	if len(req.Question) == 0 {
		return nil, false
	}

	q := req.Question[0]
	key := c.makeKey(q)
	shardIdx := c.getShardIndex(key)
	shard := c.shards[shardIdx]

	shard.mu.RLock()
	item, exists := shard.items[key]
	shard.mu.RUnlock()

	if !exists {
		return nil, false
	}

	now := time.Now()
	if now.After(item.ExpiresAt) {
		// Clean up expired item in background
		go c.delete(key)
		return nil, false
	}

	// Active Prefetching logic
	if c.prefetch && resolveFn != nil {
		totalDuration := item.ExpiresAt.Sub(now)
		remainingPercent := float64(totalDuration) / float64(time.Duration(item.OriginalTTL)*time.Second)

		if remainingPercent < 0.15 { // Less than 15% TTL remaining
			if atomic.CompareAndSwapInt32(&item.Prefetching, 0, 1) {
				// Send to background prefetch worker
				select {
				case c.prefetchChan <- prefetchRequest{
					Key:       key,
					Msg:       req,
					ResolveFn: resolveFn,
				}:
				default:
					// If channel is full, drop prefetch and reset flag
					atomic.StoreInt32(&item.Prefetching, 0)
				}
			}
		}
	}

	// Create a copy of the response message to avoid concurrent modifications,
	// and update its transaction ID to match the current request
	respCopy := item.Response.Copy()
	respCopy.Id = req.Id

	// Age the TTLs down to the entry's remaining lifetime. Serving the stored
	// TTL unchanged would let clients cache a record far beyond its validity.
	remaining := uint32(time.Until(item.ExpiresAt).Seconds())
	if remaining < 1 {
		remaining = 1
	}
	for _, section := range [][]dns.RR{respCopy.Answer, respCopy.Ns, respCopy.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue // OPT TTL carries flags, not a lifetime
			}
			if rr.Header().Ttl > remaining {
				rr.Header().Ttl = remaining
			}
		}
	}

	return respCopy, true
}

// Set adds a DNS response to the cache, computing appropriate TTL
func (c *DNSCache) Set(req *dns.Msg, resp *dns.Msg) {
	if len(req.Question) == 0 || resp == nil {
		return
	}

	q := req.Question[0]
	key := c.makeKey(q)

	// Determine cache duration from the lowest TTL in the answers
	var ttl uint32 = 0
	first := true

	for _, rr := range resp.Answer {
		rTTL := rr.Header().Ttl
		if first || rTTL < ttl {
			ttl = rTTL
			first = false
		}
	}

	for _, rr := range resp.Ns {
		rTTL := rr.Header().Ttl
		if first || rTTL < ttl {
			ttl = rTTL
			first = false
		}
	}

	// If no record has a TTL, don't cache
	if first || ttl == 0 {
		return
	}

	duration := time.Duration(ttl) * time.Second

	// Apply min/max TTL policies
	if duration < c.minTTL {
		duration = c.minTTL
	}
	if duration > c.maxTTL {
		duration = c.maxTTL
	}

	shardIdx := c.getShardIndex(key)
	shard := c.shards[shardIdx]

	shard.mu.Lock()
	// Limit size checks or simple eviction on new inserts
	if len(shard.items) > c.maxSize/64 {
		// Evict a random item or just empty the shard partially
		// (This keeps memory bounded simply and fast without heap sorting overhead)
		count := 0
		for k := range shard.items {
			delete(shard.items, k)
			count++
			if count > 10 { // Evict 10 items
				break
			}
		}
	}

	shard.items[key] = &CacheItem{
		Response:    resp.Copy(),
		ExpiresAt:   time.Now().Add(duration),
		OriginalTTL: uint32(duration.Seconds()),
	}
	shard.mu.Unlock()
}

// delete removes an item from the cache
func (c *DNSCache) delete(key string) {
	shardIdx := c.getShardIndex(key)
	shard := c.shards[shardIdx]

	shard.mu.Lock()
	delete(shard.items, key)
	shard.mu.Unlock()
}

// Clear removes all items from the cache
func (c *DNSCache) Clear() {
	for i := 0; i < 64; i++ {
		c.shards[i].mu.Lock()
		c.shards[i].items = make(map[string]*CacheItem)
		c.shards[i].mu.Unlock()
	}
}

// prefetchWorker runs in background and refreshes cache items
func (c *DNSCache) prefetchWorker() {
	for req := range c.prefetchChan {
		// Perform DNS query refresh
		newResp, err := req.ResolveFn(req.Msg)

		shardIdx := c.getShardIndex(req.Key)
		shard := c.shards[shardIdx]

		if err == nil && newResp != nil {
			c.Set(req.Msg, newResp)
		} else {
			// Reset prefetch flag if resolution failed, so we can try again
			shard.mu.Lock()
			if item, exists := shard.items[req.Key]; exists {
				atomic.StoreInt32(&item.Prefetching, 0)
			}
			shard.mu.Unlock()
		}
	}
}

// GetStats returns total cache hits/size information
func (c *DNSCache) GetStats() (size int) {
	total := 0
	for i := 0; i < 64; i++ {
		c.shards[i].mu.RLock()
		total += len(c.shards[i].items)
		c.shards[i].mu.RUnlock()
	}
	return total
}
