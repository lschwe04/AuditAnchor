package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"
)

type SecurityManager struct {
	jwtSecret []byte
}

func NewSecurityManager(secret string) *SecurityManager {
	return &SecurityManager{jwtSecret: []byte(secret)}
}

func (sm *SecurityManager) GenerateSignedJWT(tenantID, role string, scopes []string, ttl time.Duration) (string, error) {
	headerJSON, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if scopes == nil {
		scopes = []string{}
	}
	claims := map[string]any{
		"tenant_id": tenantID,
		"role":      role,
		"scopes":    scopes,
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(ttl).Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	h := hmac.New(sha256.New, sm.jwtSecret)
	h.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return unsigned + "." + sig, nil
}

func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
