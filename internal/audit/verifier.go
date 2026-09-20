package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type VerificationResult struct {
	Valid        bool   `json:"valid"`
	TotalChecked int64  `json:"total_checked"`
	BrokenAtID   *int64 `json:"broken_at_id,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

type ChainVerifier struct {
	pool *pgxpool.Pool
}

func NewChainVerifier(pool *pgxpool.Pool) *ChainVerifier {
	return &ChainVerifier{pool: pool}
}

func (cv *ChainVerifier) VerifyChain(ctx context.Context, tenantID string) (VerificationResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rows, err := cv.pool.Query(ctx, `
		SELECT id, tenant_id, action, actor, resource_id, payload::text, prev_hash, current_hash, created_at
		FROM evidence_audit_chain
		WHERE tenant_id = $1
		ORDER BY id ASC
	`, tenantID)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("failed to query audit chain for verification: %w", err)
	}
	defer rows.Close()

	expectedPrevHash := "0000000000000000000000000000000000000000000000000000000000000000"
	var count int64

	for rows.Next() {
		var id int64
		var tID, action, actor, resID, payloadStr, prevHash, currHash string
		var createdAt time.Time

		if err := rows.Scan(&id, &tID, &action, &actor, &resID, &payloadStr, &prevHash, &currHash, &createdAt); err != nil {
			return VerificationResult{}, fmt.Errorf("scan error during chain verification: %w", err)
		}

		count++
		if prevHash != expectedPrevHash {
			breakID := id
			return VerificationResult{
				Valid:        false,
				TotalChecked: count,
				BrokenAtID:   &breakID,
				Reason:       fmt.Sprintf("prev_hash mismatch at id %d: expected %s, got %s", id, expectedPrevHash, prevHash),
			}, nil
		}

		toHash := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", prevHash, tID, action, actor, resID, payloadStr, createdAt.UTC().Format(time.RFC3339Nano))
		h := sha256.Sum256([]byte(toHash))
		recomputedHash := hex.EncodeToString(h[:])

		if recomputedHash != currHash {
			breakID := id
			return VerificationResult{
				Valid:        false,
				TotalChecked: count,
				BrokenAtID:   &breakID,
				Reason:       fmt.Sprintf("current_hash mismatch at id %d: expected %s, recomputed %s", id, currHash, recomputedHash),
			}, nil
		}

		expectedPrevHash = currHash
	}

	if err := rows.Err(); err != nil {
		return VerificationResult{}, fmt.Errorf("rows iteration error: %w", err)
	}

	return VerificationResult{
		Valid:        true,
		TotalChecked: count,
	}, nil
}
