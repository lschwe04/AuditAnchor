package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
)

type contextKey string

const TenantKey contextKey = "tenant_id"

func TenantAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		authHeader := r.Header.Get("Authorization")
		if tenantID == "" || authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error":"unauthorized: missing/invalid auth"}`, http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		parts := strings.Split(tokenString, ".")
		if len(parts) != 3 {
			http.Error(w, `{"error":"unauthorized: invalid token structure"}`, http.StatusUnauthorized)
			return
		}
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			http.Error(w, `{"error":"internal server error: missing jwt secret"}`, http.StatusInternalServerError)
			return
		}

		headerPart, payloadPart, sigPart := parts[0], parts[1], parts[2]

		// HS256-Signaturprüfung über header.payload
		mac := hmac.New(sha256.New, []byte(jwtSecret))
		mac.Write([]byte(headerPart + "." + payloadPart))

		expectedSig, err := base64.RawURLEncoding.DecodeString(sigPart)
		if err != nil || !hmac.Equal(mac.Sum(nil), expectedSig) {
			http.Error(w, `{"error":"unauthorized: invalid signature"}`, http.StatusUnauthorized)
			return
		}

		// Payload decodieren
		payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadPart)
		if err != nil {
			http.Error(w, `{"error":"unauthorized: invalid payload"}`, http.StatusUnauthorized)
			return
		}

		var claims map[string]any
		if err := json.Unmarshal(payloadBytes, &claims); err != nil {
			http.Error(w, `{"error":"unauthorized: invalid claims"}`, http.StatusUnauthorized)
			return
		}

		if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
			http.Error(w, `{"error":"unauthorized: token expired"}`, http.StatusUnauthorized)
			return
		}

		if claimTenant, _ := claims["tenant_id"].(string); claimTenant != tenantID {
			http.Error(w, `{"error":"forbidden: tenant mismatch"}`, http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), TenantKey, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
