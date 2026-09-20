package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Logger struct {
	pool *pgxpool.Pool
}

func NewLogger(pool *pgxpool.Pool) *Logger {
	return &Logger{pool: pool}
}

func (l *Logger) LogEvent(ctx context.Context, tenantID, action, actor, resourceID string, payload map[string]any) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("payload marshal error: %w", err)
	}

	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx failed: %w", err)
	}
	defer tx.Rollback(ctx)

	// Advisory Lock gegen parallele First-Row-Inits oder Interleaving bei Tenant-Chains
	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenantID)
	if err != nil {
		return fmt.Errorf("advisory lock failed: %w", err)
	}

	var lastHash string
	err = tx.QueryRow(ctx, `
        SELECT current_hash FROM evidence_audit_chain 
        WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1
    `, tenantID).Scan(&lastHash)
	if err != nil {
		lastHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	now := time.Now().UTC()
	toHash := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", lastHash, tenantID, action, actor, resourceID, string(payloadBytes), now.Format(time.RFC3339Nano))
	h := sha256.Sum256([]byte(toHash))
	currHash := hex.EncodeToString(h[:])

	_, err = tx.Exec(ctx, `
        INSERT INTO evidence_audit_chain (tenant_id, action, actor, resource_id, payload, prev_hash, current_hash, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, tenantID, action, actor, resourceID, string(payloadBytes), lastHash, currHash, now)
	if err != nil {
		return fmt.Errorf("audit chain insert failed: %w", err)
	}
	return tx.Commit(ctx)
}
