package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"auditanchor/internal/audit/auth"

	"github.com/jackc/pgx/v5/pgxpool"
)

type EnrollRequest struct {
	TenantID         string `json:"tenant_id"`
	EnrollmentSecret string `json:"enrollment_secret"`
	AgentName        string `json:"agent_name"`
	// Scopes absichtlich nicht im Struct, um Client-Manipulation zu blockieren (Hotfix)
}

type EnrollHandler struct {
	pool       *pgxpool.Pool
	secManager *auth.SecurityManager
}

func NewEnrollHandler(pool *pgxpool.Pool, secManager *auth.SecurityManager) *EnrollHandler {
	return &EnrollHandler{
		pool:       pool,
		secManager: secManager,
	}
}

func (h *EnrollHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req EnrollRequest
	if err := decodeStrict(r.Body, &req); err != nil || req.TenantID == "" || req.EnrollmentSecret == "" {
		http.Error(w, `{"error":"invalid enrollment payload"}`, http.StatusBadRequest)
		return
	}

	// Multi-Agent Secret Check inkl. Revocation-Logik
	var isValid bool
	err := h.pool.QueryRow(r.Context(), `
		SELECT EXISTS (
			SELECT 1 FROM agent_enrollment_tokens 
			WHERE tenant_id = $1 AND enrollment_secret = $2 AND is_revoked = false
		)
	`, req.TenantID, req.EnrollmentSecret).Scan(&isValid)

	if err != nil || !isValid {
		http.Error(w, `{"error":"unauthorized: invalid or revoked enrollment secret"}`, http.StatusUnauthorized)
		return
	}

	// FIX F-01: Hardcoded Scopes - Ein Agent darf ausschließlich Ingest-Rechte erhalten.
	scopes := []string{"agent:ingest-only"}

	token, err := h.secManager.GenerateSignedJWT(req.TenantID, "agent-scoped", scopes, 24*time.Hour)
	if err != nil {
		http.Error(w, `{"error":"failed to generate agent token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "enrolled",
		"token":      token,
		"tenant_id":  req.TenantID,
		"scopes":     scopes,
		"expires_in": 86400,
	})
}
