package evidence

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ManifestEntry struct {
	BlobID string    `json:"blob_id"`
	Hash   string    `json:"hash"`
	Time   time.Time `json:"timestamp_utc"`
}

type AuditChainExportEntry struct {
	ID          int64           `json:"id"`
	TenantID    string          `json:"tenant_id"`
	Action      string          `json:"action"`
	Actor       string          `json:"actor"`
	ResourceID  string          `json:"resource_id"`
	Payload     json.RawMessage `json:"payload"`
	PrevHash    string          `json:"prev_hash"`
	CurrentHash string          `json:"current_hash"`
	CreatedAt   time.Time       `json:"created_at"`
}

type Exporter struct {
	pool *pgxpool.Pool
}

func NewExporter(pool *pgxpool.Pool) *Exporter {
	return &Exporter{pool: pool}
}

func (e *Exporter) StreamTenantEvidenceZIP(ctx context.Context, tenantID string, w io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	// 1. Export Evidence Blobs
	rows, err := e.pool.Query(ctx, `
		SELECT blob_id, content_hash, payload_json::text, timestamp 
		FROM evidence_blobs WHERE tenant_id = $1 ORDER BY id ASC
	`, tenantID)
	if err != nil {
		return fmt.Errorf("failed to query evidence blobs for export: %w", err)
	}

	var manifest []ManifestEntry
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("export context cancelled: %w", err)
		}
		var blobID, contentHash, payload string
		var ts time.Time
		if err := rows.Scan(&blobID, &contentHash, &payload, &ts); err != nil {
			rows.Close()
			return fmt.Errorf("row scan error on evidence blobs: %w", err)
		}
		manifest = append(manifest, ManifestEntry{BlobID: blobID, Hash: contentHash, Time: ts.UTC()})

		f, err := zipWriter.Create(fmt.Sprintf("blobs/%s.json", blobID))
		if err != nil {
			rows.Close()
			return fmt.Errorf("zip entry creation failed for blob %s: %w", blobID, err)
		}
		if _, err := io.WriteString(f, payload); err != nil {
			rows.Close()
			return fmt.Errorf("zip write failed for blob %s: %w", blobID, err)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("blob rows iteration error: %w", err)
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("manifest marshal error: %w", err)
	}
	manifestFile, err := zipWriter.Create("manifest.json")
	if err != nil {
		return fmt.Errorf("manifest zip entry creation failed: %w", err)
	}
	if _, err := manifestFile.Write(manifestBytes); err != nil {
		return fmt.Errorf("manifest write failed: %w", err)
	}

	// 2. Export Audit Chain (GoBD-konform)
	chainRows, err := e.pool.Query(ctx, `
		SELECT id, tenant_id, action, actor, resource_id, payload::text, prev_hash, current_hash, created_at
		FROM evidence_audit_chain WHERE tenant_id = $1 ORDER BY id ASC
	`, tenantID)
	if err != nil {
		return fmt.Errorf("failed to query audit chain for export: %w", err)
	}

	var auditEntries []AuditChainExportEntry
	for chainRows.Next() {
		if err := ctx.Err(); err != nil {
			chainRows.Close()
			return fmt.Errorf("export context cancelled during chain export: %w", err)
		}
		var entry AuditChainExportEntry
		var payloadRaw string
		if err := chainRows.Scan(&entry.ID, &entry.TenantID, &entry.Action, &entry.Actor, &entry.ResourceID, &payloadRaw, &entry.PrevHash, &entry.CurrentHash, &entry.CreatedAt); err != nil {
			chainRows.Close()
			return fmt.Errorf("audit chain scan error: %w", err)
		}
		entry.Payload = json.RawMessage(payloadRaw)
		entry.CreatedAt = entry.CreatedAt.UTC()
		auditEntries = append(auditEntries, entry)
	}
	chainRows.Close()
	if err := chainRows.Err(); err != nil {
		return fmt.Errorf("audit chain rows iteration error: %w", err)
	}

	auditBytes, err := json.MarshalIndent(auditEntries, "", "  ")
	if err != nil {
		return fmt.Errorf("audit entries marshal error: %w", err)
	}
	auditFile, err := zipWriter.Create("audit_chain.json")
	if err != nil {
		return fmt.Errorf("audit_chain zip entry creation failed: %w", err)
	}
	if _, err := auditFile.Write(auditBytes); err != nil {
		return fmt.Errorf("audit_chain write failed: %w", err)
	}

	return nil
}
