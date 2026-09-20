package handlers

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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
	if tenantID == "" {
		http.Error(w, `{"error":"missing tenant context"}`, http.StatusUnauthorized)
		return
	}

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
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		http.Error(w, `{"error":"transaction start failed"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// 1. Blob insert
	_, err = tx.Exec(ctx, `
        INSERT INTO evidence_blobs (blob_id, tenant_id, content_hash, payload_json, timestamp, hmac_sig)
        VALUES ($1, $2, $3, $4, $5, $6)
    `, blobID, tenantID, contentHash, string(payloadBytes), tsToken.Timestamp, tsToken.HMACSig)
	if err != nil {
		http.Error(w, `{"error":"database insert failed"}`, http.StatusInternalServerError)
		return
	}

	// 2. Transaktionaler Audit-Log Chaining Check
	// FIX: Exakt dieselbe 64-Bit Hash-Logik für den Advisory-Lock wie in audit.go verwenden
	hLock := sha256.Sum256([]byte(tenantID))
	lockID := int64(binary.BigEndian.Uint64(hLock[:8]))
	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID)
	if err != nil {
		http.Error(w, `{"error":"advisory lock failed"}`, http.StatusInternalServerError)
		return
	}

	var lastHash string
	// FIX: FOR UPDATE verwenden, um Konsistenz zu erzwingen
	err = tx.QueryRow(ctx, `
        SELECT current_hash FROM evidence_audit_chain 
        WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1 FOR UPDATE
    `, tenantID).Scan(&lastHash)
	if err != nil {
		lastHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	auditPayloadBytes, _ := json.Marshal(map[string]any{"hash": contentHash})
	now := time.Now().UTC()
	toHash := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", lastHash, tenantID, "EVIDENCE_INGEST", "vault-api", blobID, string(auditPayloadBytes), now.Format(time.RFC3339Nano))
	hBytes := sha256.Sum256([]byte(toHash))
	currHash := hex.EncodeToString(hBytes[:])

	_, err = tx.Exec(ctx, `
        INSERT INTO evidence_audit_chain (tenant_id, action, actor, resource_id, payload, prev_hash, current_hash, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, tenantID, "EVIDENCE_INGEST", "vault-api", blobID, string(auditPayloadBytes), lastHash, currHash, now)
	if err != nil {
		http.Error(w, `{"error":"audit log failed"}`, http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, `{"error":"commit failed"}`, http.StatusInternalServerError)
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
