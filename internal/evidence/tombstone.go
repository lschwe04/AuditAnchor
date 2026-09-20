package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type TombstoneService struct {
	pool *pgxpool.Pool
}

func NewTombstoneService(pool *pgxpool.Pool) *TombstoneService {
	return &TombstoneService{pool: pool}
}

func (ts *TombstoneService) ExecuteTombstone(ctx context.Context, tenantID, blobID, actor, reason string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	tx, err := ts.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to begin tombstone tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// FIX: Identischer globaler 64-Bit Hash-Advisory-Lock wie im gesamten System
	hLock := sha256.Sum256([]byte(tenantID))
	lockID := int64(binary.BigEndian.Uint64(hLock[:8]))
	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID)
	if err != nil {
		return "", fmt.Errorf("advisory lock failed: %w", err)
	}

	var existingHash string
	err = tx.QueryRow(ctx, `
		SELECT content_hash FROM evidence_blobs 
		WHERE blob_id = $1 AND tenant_id = $2 FOR UPDATE
	`, blobID, tenantID).Scan(&existingHash)
	if err != nil {
		return "", fmt.Errorf("blob not found or scope mismatch: %w", err)
	}

	tombstonePayload, _ := json.Marshal(map[string]any{
		"_dsgvo_tombstone": true,
		"original_hash":    existingHash,
		"redacted_at":      time.Now().UTC().Format(time.RFC3339Nano),
		"reason":           reason,
	})

	_, err = tx.Exec(ctx, `
		UPDATE evidence_blobs 
		SET payload_json = $1::jsonb 
		WHERE blob_id = $2 AND tenant_id = $3
	`, string(tombstonePayload), blobID, tenantID)
	if err != nil {
		return "", fmt.Errorf("failed to update blob with tombstone: %w", err)
	}

	var lastHash string
	err = tx.QueryRow(ctx, `
		SELECT current_hash FROM evidence_audit_chain 
		WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1 FOR UPDATE
	`, tenantID).Scan(&lastHash)
	if err != nil {
		lastHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	now := time.Now().UTC()
	payloadMap := map[string]any{
		"redacted_blob_id": blobID,
		"original_hash":    existingHash,
		"reason":           reason,
	}
	payloadBytes, _ := json.Marshal(payloadMap)
	toHash := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", lastHash, tenantID, "EVIDENCE_TOMBSTONE", actor, blobID, string(payloadBytes), now.Format(time.RFC3339Nano))
	hBytes := sha256.Sum256([]byte(toHash))
	currHash := hex.EncodeToString(hBytes[:])

	_, err = tx.Exec(ctx, `
		INSERT INTO evidence_audit_chain (tenant_id, action, actor, resource_id, payload, prev_hash, current_hash, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, tenantID, "EVIDENCE_TOMBSTONE", actor, blobID, string(payloadBytes), lastHash, currHash, now)
	if err != nil {
		return "", fmt.Errorf("failed to insert tombstone audit event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit failed for tombstone: %w", err)
	}

	return existingHash, nil
}
