package handlers

import (
	"encoding/json"
	"net/http"

	"auditanchor/internal/audit"
	"auditanchor/internal/audit/auth"
)

type VerifyHandler struct {
	verifier *audit.ChainVerifier
}

func NewVerifyHandler(verifier *audit.ChainVerifier) *VerifyHandler {
	return &VerifyHandler{verifier: verifier}
}

func (h *VerifyHandler) Verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	tenantID, ok := r.Context().Value(auth.TenantKey).(string)
	if !ok || tenantID == "" {
		http.Error(w, `{"error":"unauthorized tenant context"}`, http.StatusUnauthorized)
		return
	}

	result, err := h.verifier.VerifyChain(r.Context(), tenantID)
	if err != nil {
		http.Error(w, `{"error":"verification failed internally"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
