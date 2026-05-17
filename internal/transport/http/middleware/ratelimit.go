package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type window struct {
	count int
	reset time.Time
}

type IPRateLimiter struct {
	mu      sync.Mutex
	windows map[string]*window
	limit   int
	period  time.Duration
}

func NewIPRateLimiter(limit int, period time.Duration) *IPRateLimiter {
	rl := &IPRateLimiter{
		windows: make(map[string]*window),
		limit:   limit,
		period:  period,
	}
	go rl.cleanup()
	return rl
}

func (rl *IPRateLimiter) cleanup() {
	for {
		time.Sleep(rl.period * 5)
		now := time.Now()
		rl.mu.Lock()
		for ip, w := range rl.windows {
			if now.After(w.reset) {
				delete(rl.windows, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *IPRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	w, ok := rl.windows[ip]
	if !ok || now.After(w.reset) {
		rl.windows[ip] = &window{count: 1, reset: now.Add(rl.period)}
		return true
	}
	if w.count >= rl.limit {
		return false
	}
	w.count++
	return true
}

func (rl *IPRateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			if !rl.allow(ip) {
				http.Error(w, `{"error":"too many requests"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}