package forwarder

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Upstream represents a single upstream DNS server with tracked metrics
type Upstream struct {
	Address  string
	RTT      int64 // Average RTT in microseconds (atomic)
	Failures int32 // Consecutive failures (atomic)
	LastSeen time.Time
	mu       sync.RWMutex
}

// Global Upstream Registry to share metrics across dynamically created forwarder instances
var (
	upstreamsRegistry = make(map[string]*Upstream)
	registryMu        sync.RWMutex
)

func getOrCreateUpstream(addr string) *Upstream {
	registryMu.RLock()
	u, exists := upstreamsRegistry[addr]
	registryMu.RUnlock()
	if exists {
		return u
	}

	registryMu.Lock()
	defer registryMu.Unlock()
	if u, exists = upstreamsRegistry[addr]; exists {
		return u
	}

	u = &Upstream{
		Address: addr,
		RTT:     20000, // Initialize with 20ms starting RTT
	}
	upstreamsRegistry[addr] = u
	return u
}

// SmartForwarder handles forwarding DNS queries to the fastest, healthiest upstream servers
type SmartForwarder struct {
	upstreams []*Upstream
	failovers []*Upstream
	client    *dns.Client
	mu        sync.RWMutex
}

// New creates a new SmartForwarder instance
func New(addresses []string, failovers []string) *SmartForwarder {
	f := &SmartForwarder{
		client: &dns.Client{
			Net:     "udp",
			Timeout: 2 * time.Second,
		},
	}

	for _, addr := range addresses {
		f.upstreams = append(f.upstreams, getOrCreateUpstream(addr))
	}

	for _, addr := range failovers {
		f.failovers = append(f.failovers, getOrCreateUpstream(addr))
	}

	return f
}

// SetUpstreams atomically replaces the resolver pool. Metrics for addresses that
// remain configured are preserved via the shared upstream registry.
func (f *SmartForwarder) SetUpstreams(addresses []string, failovers []string) {
	primary := make([]*Upstream, 0, len(addresses))
	for _, addr := range addresses {
		primary = append(primary, getOrCreateUpstream(addr))
	}
	backup := make([]*Upstream, 0, len(failovers))
	for _, addr := range failovers {
		backup = append(backup, getOrCreateUpstream(addr))
	}

	f.mu.Lock()
	f.upstreams = primary
	f.failovers = backup
	f.mu.Unlock()
}

// Forward resolves a DNS request by forwarding it to the best available upstream.
// It falls back to failover upstreams if primary ones are down.
func (f *SmartForwarder) Forward(req *dns.Msg) (*dns.Msg, error) {
	resp, _, err := f.ForwardWithSource(req)
	return resp, err
}

// ForwardWithSource behaves like Forward but also reports the address of the
// upstream that produced the answer, for query logging.
func (f *SmartForwarder) ForwardWithSource(req *dns.Msg) (*dns.Msg, string, error) {
	bestUpstreams := f.getSortedHealthyUpstreams(f.upstreams)
	var lastErr error

	if len(bestUpstreams) > 0 {
		fastestRTT := atomic.LoadInt64(&bestUpstreams[0].RTT)
		if len(bestUpstreams) >= 2 && fastestRTT > 60000 { // 60ms in microseconds
			resp, source, err := f.forwardParallel(req, bestUpstreams[0], bestUpstreams[1])
			if err == nil {
				return resp, source, nil
			}
			lastErr = err
		} else {
			resp, err := f.forwardSingle(req, bestUpstreams[0])
			if err == nil {
				return resp, bestUpstreams[0].Address, nil
			}
			lastErr = err
		}
	}

	// Failover mechanism: try configured failover upstreams if primaries are degraded/failed
	bestFailovers := f.getSortedHealthyUpstreams(f.failovers)
	if len(bestFailovers) > 0 {
		resp, err := f.forwardSingle(req, bestFailovers[0])
		if err == nil {
			return resp, bestFailovers[0].Address, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, "", lastErr
	}
	return nil, "", errors.New("no healthy upstream servers available")
}

// forwardSingle queries a single upstream and records performance metrics
func (f *SmartForwarder) forwardSingle(req *dns.Msg, u *Upstream) (*dns.Msg, error) {
	start := time.Now()
	resp, _, err := f.client.Exchange(req, u.Address)
	rtt := time.Since(start)

	if err != nil {
		f.recordFailure(u)
		return nil, err
	}

	// A truncated UDP answer carries no usable records, so the query must be
	// repeated over TCP. Large RRsets (long TXT or DNSSEC-signed responses)
	// would otherwise be returned empty.
	if resp != nil && resp.Truncated {
		if tcpResp, retryErr := f.exchangeTCP(req, u.Address); retryErr == nil && tcpResp != nil {
			f.recordSuccess(u, time.Since(start))
			return tcpResp, nil
		}
		// Keep the truncated answer rather than failing the query outright:
		// the client can retry over TCP itself.
	}

	f.recordSuccess(u, rtt)
	return resp, nil
}

// exchangeTCP repeats a query over TCP, used to recover truncated answers.
func (f *SmartForwarder) exchangeTCP(req *dns.Msg, address string) (*dns.Msg, error) {
	tcpClient := &dns.Client{Net: "tcp", Timeout: f.client.Timeout}
	resp, _, err := tcpClient.Exchange(req, address)
	return resp, err
}

// forwardParallel queries two upstreams concurrently and returns the fastest
// successful result along with the address that produced it.
func (f *SmartForwarder) forwardParallel(req *dns.Msg, u1, u2 *Upstream) (*dns.Msg, string, error) {
	type result struct {
		resp *dns.Msg
		err  error
		u    *Upstream
		rtt  time.Duration
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := make(chan result, 2)

	query := func(u *Upstream) {
		start := time.Now()
		resp, _, err := f.client.ExchangeContext(ctx, req.Copy(), u.Address)
		rtt := time.Since(start)
		ch <- result{resp: resp, err: err, u: u, rtt: rtt}
	}

	go query(u1)
	go query(u2)

	var firstErr error
	for i := 0; i < 2; i++ {
		res := <-ch
		if res.err == nil && res.resp != nil {
			f.recordSuccess(res.u, res.rtt)
			cancel() // Abort the other request
			// Same truncation rule as the single-upstream path.
			if res.resp.Truncated {
				if tcpResp, retryErr := f.exchangeTCP(req, res.u.Address); retryErr == nil && tcpResp != nil {
					return tcpResp, res.u.Address, nil
				}
			}
			return res.resp, res.u.Address, nil
		}

		f.recordFailure(res.u)
		if firstErr == nil {
			firstErr = res.err
		}
	}

	return nil, "", firstErr
}

// getSortedHealthyUpstreams returns upstreams sorted by their average RTT.
func (f *SmartForwarder) getSortedHealthyUpstreams(list []*Upstream) []*Upstream {
	f.mu.RLock()
	defer f.mu.RUnlock()

	sorted := make([]*Upstream, len(list))
	copy(sorted, list)

	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			uI := sorted[i]
			uJ := sorted[j]

			failsI := atomic.LoadInt32(&uI.Failures)
			failsJ := atomic.LoadInt32(&uJ.Failures)

			rttI := atomic.LoadInt64(&uI.RTT)
			rttJ := atomic.LoadInt64(&uJ.RTT)

			degradedI := failsI >= 3
			degradedJ := failsJ >= 3

			swap := false
			if degradedI && !degradedJ {
				swap = true
			} else if !degradedI && degradedJ {
				swap = false
			} else {
				swap = rttI > rttJ
			}

			if swap {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	return sorted
}

// recordSuccess calculates the Exponentially Weighted Moving Average (EWMA) of the RTT
func (f *SmartForwarder) recordSuccess(u *Upstream, rtt time.Duration) {
	rttMicro := rtt.Microseconds()
	atomic.StoreInt32(&u.Failures, 0) // Reset failures

	u.mu.Lock()
	u.LastSeen = time.Now()
	u.mu.Unlock()

	for {
		oldRTT := atomic.LoadInt64(&u.RTT)
		newRTT := int64(math.Round(0.85*float64(oldRTT) + 0.15*float64(rttMicro)))
		if atomic.CompareAndSwapInt64(&u.RTT, oldRTT, newRTT) {
			break
		}
	}
}

// recordFailure increments the failure count and increases RTT score as a penalty
func (f *SmartForwarder) recordFailure(u *Upstream) {
	atomic.AddInt32(&u.Failures, 1)

	for {
		oldRTT := atomic.LoadInt64(&u.RTT)
		newRTT := int64(float64(oldRTT) * 1.5)
		if newRTT > 2000000 { // 2 seconds in microseconds
			newRTT = 2000000
		}
		if atomic.CompareAndSwapInt64(&u.RTT, oldRTT, newRTT) {
			break
		}
	}
}

// GetStats returns upstreams metrics
type UpstreamStat struct {
	Address  string  `json:"address"`
	RTTMs    float64 `json:"rtt_ms"`
	Failures int     `json:"failures"`
}

func (f *SmartForwarder) GetStats() []UpstreamStat {
	f.mu.RLock()
	defer f.mu.RUnlock()

	stats := make([]UpstreamStat, 0, len(f.upstreams)+len(f.failovers))
	for _, u := range f.upstreams {
		rttMicro := atomic.LoadInt64(&u.RTT)
		fails := atomic.LoadInt32(&u.Failures)
		stats = append(stats, UpstreamStat{
			Address:  u.Address,
			RTTMs:    float64(rttMicro) / 1000.0,
			Failures: int(fails),
		})
	}
	for _, u := range f.failovers {
		rttMicro := atomic.LoadInt64(&u.RTT)
		fails := atomic.LoadInt32(&u.Failures)
		stats = append(stats, UpstreamStat{
			Address:  u.Address,
			RTTMs:    float64(rttMicro) / 1000.0,
			Failures: int(fails),
		})
	}
	return stats
}
