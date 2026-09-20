package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"auditanchor/internal/audit/auth"
)

type EnrollRequest struct {
	TenantID         string   `json:"tenant_id"`
	EnrollmentSecret string   `json:"enrollment_secret"`
	AgentName        string   `json:"agent_name"`
	Scopes           []string `json:"scopes"`
}

type EnrollHandler struct {
	expectedSecret string
	secManager     *auth.SecurityManager
}

func NewEnrollHandler(expectedSecret string, secManager *auth.SecurityManager) *EnrollHandler {
	return &EnrollHandler{
		expectedSecret: expectedSecret,
		secManager:     secManager,
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

	if req.EnrollmentSecret != h.expectedSecret {
		http.Error(w, `{"error":"unauthorized: invalid enrollment secret"}`, http.StatusUnauthorized)
		return
	}

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"agent:ingest-only"}
	}

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
