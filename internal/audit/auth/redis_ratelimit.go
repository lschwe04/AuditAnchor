package auth

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisRateLimitScript = `
local current = redis.call('INCR', KEYS)
if current == 1 then redis.call('PEXPIRE', KEYS, ARGV) end
return current
`

type RedisRateLimiter struct {
	client *redis.Client
	limit  int64
	window time.Duration
}

func NewRedisRateLimiter(client *redis.Client, limit int64, window time.Duration) *RedisRateLimiter {
	if client == nil {
		return &RedisRateLimiter{limit: limit, window: window}
	}
	return &RedisRateLimiter{client: client, limit: limit, window: window}
}

func (l *RedisRateLimiter) Allow(ctx context.Context, tenantID string) (bool, error) {
	if l.client == nil {
		return true, nil
	}
	windowID := time.Now().UTC().UnixMilli() / l.window.Milliseconds()
	key := "vault:ratelimit:tenant:" + strings.TrimSpace(tenantID) + ":" + strconv.FormatInt(windowID, 10)
	count, err := l.client.Eval(ctx, redisRateLimitScript, []string{key}, l.window.Milliseconds()).Int64()
	if err != nil {
		return false, err
	}
	return count <= l.limit, nil
}

func RedisRateLimitMiddleware(limiter *RedisRateLimiter, failClosed bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID, _ := r.Context().Value(TenantKey).(string)
		allowed, err := limiter.Allow(r.Context(), tenantID)
		if err != nil && failClosed {
			http.Error(w, `{"error":"rate limiter unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
