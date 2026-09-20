package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"auditanchor/internal/audit/auth"
	"auditanchor/internal/evidence"
)

type TombstoneRequest struct {
	BlobID string `json:"blob_id"`
	Reason string `json:"reason"`
}

type TombstoneHandler struct {
	service *evidence.TombstoneService
}

func NewTombstoneHandler(service *evidence.TombstoneService) *TombstoneHandler {
	return &TombstoneHandler{service: service}
}

func decodeStrict(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func (h *TombstoneHandler) Tombstone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	tenantID, ok := r.Context().Value(auth.TenantKey).(string)
	if !ok || tenantID == "" {
		http.Error(w, `{"error":"unauthorized tenant context"}`, http.StatusUnauthorized)
		return
	}

	var req TombstoneRequest
	if err := decodeStrict(r.Body, &req); err != nil || req.BlobID == "" {
		http.Error(w, `{"error":"invalid json or missing blob_id"}`, http.StatusBadRequest)
		return
	}

	originalHash, err := h.service.ExecuteTombstone(r.Context(), tenantID, req.BlobID, "dsgvo-officer", req.Reason)
	if err != nil {
		http.Error(w, `{"error":"tombstone execution failed"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "tombstoned",
		"blob_id":       req.BlobID,
		"original_hash": originalHash,
	})
}
