// Package store provides GateSignal's durable Redis-compatible state.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var updateCounterScript = redis.NewScript(`
local observed = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local is_error = tonumber(ARGV[3])
local suspicious = tonumber(ARGV[4])
local first = tonumber(redis.call('HGET', KEYS[1], 'first_seen'))
if not first or observed < first or observed - first >= window then
  redis.call('DEL', KEYS[1])
  first = observed
  redis.call('HSET', KEYS[1], 'first_seen', first, 'count', 0, 'errors', 0, 'successes', 0, 'suspicious', 0)
end
redis.call('HSET', KEYS[1], 'last_seen', observed)
redis.call('HINCRBY', KEYS[1], 'count', 1)
if is_error == 1 then
  redis.call('HINCRBY', KEYS[1], 'errors', 1)
else
  redis.call('HINCRBY', KEYS[1], 'successes', 1)
end
if suspicious == 1 then redis.call('HSET', KEYS[1], 'suspicious', 1) end
redis.call('PEXPIRE', KEYS[1], window * 2)
return redis.call('HMGET', KEYS[1], 'first_seen', 'last_seen', 'count', 'errors', 'successes', 'suspicious')
`)

var renewLeaseScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 0
`)

var releaseLeaseScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`)

type Store struct {
	client *redis.Client
	prefix string
}

type Counter struct {
	FirstSeen  time.Time
	LastSeen   time.Time
	Count      int
	Errors     int
	Successes  int
	Suspicious bool
}

func New(address, password string, db int, namespace string) *Store {
	return &Store{
		client: redis.NewClient(&redis.Options{Addr: address, Password: password, DB: db}),
		prefix: strings.TrimSuffix(namespace, ":") + ":",
	}
}

func (s *Store) Close() error                   { return s.client.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.client.Ping(ctx).Err() }
func (s *Store) Client() *redis.Client          { return s.client }
func (s *Store) Key(parts ...string) string     { return s.prefix + strings.Join(parts, ":") }

func (s *Store) CounterKey(host, site, ip string) string {
	digest := sha256.Sum256([]byte(host + "\x00" + site + "\x00" + ip))
	return s.Key("signals", "counter", hex.EncodeToString(digest[:16]))
}

func (s *Store) UpdateCounter(ctx context.Context, key string, observed time.Time, window time.Duration, isError, suspicious bool) (Counter, error) {
	result, err := updateCounterScript.Run(ctx, s.client, []string{key}, observed.UnixMilli(), window.Milliseconds(), boolInt(isError), boolInt(suspicious)).Slice()
	if err != nil {
		return Counter{}, err
	}
	if len(result) != 6 {
		return Counter{}, fmt.Errorf("counter script returned %d values", len(result))
	}
	values := make([]int64, len(result))
	for i, value := range result {
		values[i], err = toInt64(value)
		if err != nil {
			return Counter{}, err
		}
	}
	return Counter{
		FirstSeen: time.UnixMilli(values[0]).UTC(), LastSeen: time.UnixMilli(values[1]).UTC(),
		Count: int(values[2]), Errors: int(values[3]), Successes: int(values[4]), Suspicious: values[5] == 1,
	}, nil
}

func (s *Store) ResetCounter(ctx context.Context, key string, expectedCount int) error {
	const script = `if tonumber(redis.call('HGET', KEYS[1], 'count')) == tonumber(ARGV[1]) then return redis.call('DEL', KEYS[1]) else return 0 end`
	return s.client.Eval(ctx, script, []string{key}, expectedCount).Err()
}

func (s *Store) EnqueueJSON(ctx context.Context, key string, value any, max int64) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	pipe := s.client.TxPipeline()
	pipe.RPush(ctx, key, raw)
	if max > 0 {
		pipe.LTrim(ctx, key, -max, -1)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (s *Store) PeekQueue(ctx context.Context, key string, max int64) ([]string, error) {
	if max <= 0 {
		return nil, nil
	}
	return s.client.LRange(ctx, key, 0, max-1).Result()
}

func (s *Store) DropQueue(ctx context.Context, key string, count int64) error {
	if count <= 0 {
		return nil
	}
	return s.client.LTrim(ctx, key, count, -1).Err()
}

func (s *Store) QueueLength(ctx context.Context, key string) (int64, error) {
	return s.client.LLen(ctx, key).Result()
}

func (s *Store) AcquireLease(ctx context.Context, key, token string, ttl time.Duration) (bool, error) {
	return s.client.SetNX(ctx, key, token, ttl).Result()
}

func (s *Store) RenewLease(ctx context.Context, key, token string, ttl time.Duration) (bool, error) {
	result, err := renewLeaseScript.Run(ctx, s.client, []string{key}, token, ttl.Milliseconds()).Int64()
	return result == 1, err
}

func (s *Store) ReleaseLease(ctx context.Context, key, token string) (bool, error) {
	result, err := releaseLeaseScript.Run(ctx, s.client, []string{key}, token).Int64()
	return result == 1, err
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func toInt64(value any) (int64, error) {
	switch value := value.(type) {
	case int64:
		return value, nil
	case string:
		var parsed int64
		_, err := fmt.Sscan(value, &parsed)
		return parsed, err
	default:
		return 0, fmt.Errorf("unexpected Redis integer type %T", value)
	}
}
