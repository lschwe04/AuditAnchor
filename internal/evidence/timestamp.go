package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type TimestampService struct {
	hmacSecret []byte
}

type TimestampToken struct {
	Digest    string    `json:"digest"`
	Timestamp time.Time `json:"timestamp"`
	HMACSig   string    `json:"hmac_signature"`
}

func NewTimestampService(secret string) *TimestampService {
	return &TimestampService{hmacSecret: []byte(secret)}
}

func (ts *TimestampService) Stamp(payload []byte) TimestampToken {
	now := time.Now().UTC()
	h := sha256.Sum256(payload)
	digest := hex.EncodeToString(h[:])

	mac := hmac.New(sha256.New, ts.hmacSecret)
	mac.Write([]byte(digest + "|" + now.Format(time.RFC3339Nano)))
	sig := hex.EncodeToString(mac.Sum(nil))

	return TimestampToken{
		Digest:    digest,
		Timestamp: now,
		HMACSig:   sig,
	}
}
