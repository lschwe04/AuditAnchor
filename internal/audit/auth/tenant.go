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

const (
	TenantKey contextKey = "tenant_id"
	ScopeKey  contextKey = "scopes"
)

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
		mac := hmac.New(sha256.New, []byte(jwtSecret))
		mac.Write([]byte(headerPart + "." + payloadPart))

		expectedSig, err := base64.RawURLEncoding.DecodeString(sigPart)
		if err != nil || !hmac.Equal(mac.Sum(nil), expectedSig) {
			http.Error(w, `{"error":"unauthorized: invalid signature"}`, http.StatusUnauthorized)
			return
		}

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

		var scopes []string
		if rawScopes, ok := claims["scopes"].([]any); ok {
			for _, s := range rawScopes {
				if str, ok := s.(string); ok {
					scopes = append(scopes, str)
				}
			}
		}

		ctx := context.WithValue(r.Context(), TenantKey, tenantID)
		ctx = context.WithValue(ctx, ScopeKey, scopes)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RequireScope(requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scopes, ok := r.Context().Value(ScopeKey).([]string)
			if !ok {
				http.Error(w, `{"error":"forbidden: missing scopes"}`, http.StatusForbidden)
				return
			}
			hasScope := false
			for _, s := range scopes {
				if s == requiredScope || s == "*" {
					hasScope = true
					break
				}
			}
			if !hasScope {
				http.Error(w, `{"error":"forbidden: insufficient scope"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
