package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"auditanchor/internal/audit"
	"auditanchor/internal/audit/auth"
	"auditanchor/internal/evidence"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type IngestRequest struct {
	Payload map[string]any `json:"payload"`
}

type IngestHandler struct {
	pool        *pgxpool.Pool
	auditLogger *audit.Logger
	tsService   *evidence.TimestampService
}

func NewIngestHandler(p *pgxpool.Pool, al *audit.Logger, ts *evidence.TimestampService) *IngestHandler {
	return &IngestHandler{pool: p, auditLogger: al, tsService: ts}
}

func (h *IngestHandler) Ingest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	tenantID, _ := r.Context().Value(auth.TenantKey).(string)

	var req IngestRequest
	if err := decodeStrict(r.Body, &req); err != nil {
		http.Error(w, `{"error":"invalid or unknown fields in json"}`, http.StatusBadRequest)
		return
	}

	payloadBytes, err := json.Marshal(req.Payload)
	if err != nil {
		http.Error(w, `{"error":"failed to marshal payload"}`, http.StatusBadRequest)
		return
	}
	hashSum := sha256.Sum256(payloadBytes)
	contentHash := hex.EncodeToString(hashSum[:])
	blobID := uuid.New().String()
	tsToken := h.tsService.Stamp(payloadBytes)

	ctx := r.Context()
	_, err = h.pool.Exec(ctx, `
        INSERT INTO evidence_blobs (blob_id, tenant_id, content_hash, payload_json, timestamp, hmac_sig)
        VALUES ($1, $2, $3, $4, $5, $6)
    `, blobID, tenantID, contentHash, string(payloadBytes), tsToken.Timestamp, tsToken.HMACSig)
	if err != nil {
		http.Error(w, `{"error":"database insert failed"}`, http.StatusInternalServerError)
		return
	}

	if err := h.auditLogger.LogEvent(ctx, tenantID, "EVIDENCE_INGEST", "vault-api", blobID, map[string]any{
		"hash": contentHash,
	}); err != nil {
		http.Error(w, `{"error":"audit log failed"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ingested",
		"blob_id": blobID,
		"hash":    contentHash,
	})
}
