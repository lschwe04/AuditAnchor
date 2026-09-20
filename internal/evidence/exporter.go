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
	BlobID string `json:"blob_id"`
	Hash   string `json:"hash"`
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
	zipWriter := zip.NewWriter(w)
	defer func() {
		_ = zipWriter.Close()
	}()

	// GoBD Verfahrensdokumentation Eckdaten (meta.txt)
	var minTs, maxTs *time.Time
	_ = e.pool.QueryRow(ctx, `SELECT MIN(timestamp), MAX(timestamp) FROM evidence_blobs WHERE tenant_id = $1`, tenantID).Scan(&minTs, &maxTs)

	startStr := "N/A"
	endStr := "N/A"
	if minTs != nil {
		startStr = minTs.UTC().Format(time.RFC3339)
	}
	if maxTs != nil {
		endStr = maxTs.UTC().Format(time.RFC3339)
	}

	metaContent := fmt.Sprintf(
		"=== GoBD VERFAHRENSDOKUMENTATION METADATEN ===\n"+
			"Mandant (Tenant-ID): %s\n"+
			"Prüfzeitraum von: %s\n"+
			"Prüfzeitraum bis: %s\n"+
			"Export-Timestamp (UTC): %s\n"+
			"Integritätssicherung: SHA-256 Chaining + HMAC-Timestamping\n",
		tenantID, startStr, endStr, time.Now().UTC().Format(time.RFC3339),
	)
	if mf, err := zipWriter.Create("meta.txt"); err == nil {
		_, _ = mf.Write([]byte(metaContent))
	}

	// 1. Export Evidence Blobs
	rows, err := e.pool.Query(ctx, `
        SELECT blob_id, content_hash, payload_json::text, timestamp 
        FROM evidence_blobs WHERE tenant_id = $1 ORDER BY id ASC
    `, tenantID)
	if err != nil {
		return fmt.Errorf("failed to query evidence blobs: %w", err)
	}
	defer rows.Close()

	var manifest []ManifestEntry
	for rows.Next() {
		var blobID, contentHash, payload string
		var ts time.Time
		if err := rows.Scan(&blobID, &contentHash, &payload, &ts); err != nil {
			return fmt.Errorf("scan error on evidence blob: %w", err)
		}
		manifest = append(manifest, ManifestEntry{BlobID: blobID, Hash: contentHash})

		f, err := zipWriter.Create(fmt.Sprintf("blobs/%s.json", blobID))
		if err != nil {
			return fmt.Errorf("failed to create zip entry for blob %s: %w", blobID, err)
		}
		if _, err := f.Write([]byte(payload)); err != nil {
			return fmt.Errorf("failed to write blob %s to zip: %w", blobID, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("blob rows iteration error: %w", err)
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}
	manifestFile, err := zipWriter.Create("manifest.json")
	if err != nil {
		return fmt.Errorf("failed to create manifest.json in zip: %w", err)
	}
	if _, err := manifestFile.Write(manifestBytes); err != nil {
		return fmt.Errorf("failed to write manifest.json: %w", err)
	}

	// 2. Export Audit Chain
	chainRows, err := e.pool.Query(ctx, `
        SELECT id, tenant_id, action, actor, resource_id, payload::text, prev_hash, current_hash, created_at
        FROM evidence_audit_chain WHERE tenant_id = $1 ORDER BY id ASC
    `, tenantID)
	if err != nil {
		return fmt.Errorf("failed to query audit chain: %w", err)
	}
	defer chainRows.Close()

	var auditEntries []AuditChainExportEntry
	for chainRows.Next() {
		var entry AuditChainExportEntry
		var payloadRaw string
		if err := chainRows.Scan(&entry.ID, &entry.TenantID, &entry.Action, &entry.Actor, &entry.ResourceID, &payloadRaw, &entry.PrevHash, &entry.CurrentHash, &entry.CreatedAt); err != nil {
			return fmt.Errorf("scan error on audit chain: %w", err)
		}
		entry.Payload = json.RawMessage(payloadRaw)
		auditEntries = append(auditEntries, entry)
	}
	if err := chainRows.Err(); err != nil {
		return fmt.Errorf("audit chain rows iteration error: %w", err)
	}

	auditBytes, err := json.MarshalIndent(auditEntries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal audit chain: %w", err)
	}
	auditFile, err := zipWriter.Create("audit_chain.json")
	if err != nil {
		return fmt.Errorf("failed to create audit_chain.json in zip: %w", err)
	}
	if _, err := auditFile.Write(auditBytes); err != nil {
		return fmt.Errorf("failed to write audit_chain.json: %w", err)
	}

	return nil
}
