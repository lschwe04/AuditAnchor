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
	defer zipWriter.Close()

	// 1. Export Evidence Blobs
	rows, err := e.pool.Query(ctx, `
        SELECT blob_id, content_hash, payload_json::text, timestamp 
        FROM evidence_blobs WHERE tenant_id = $1 ORDER BY id ASC
    `, tenantID)
	if err != nil {
		return err
	}

	var manifest []ManifestEntry
	for rows.Next() {
		var blobID, contentHash, payload string
		var ts time.Time
		if err := rows.Scan(&blobID, &contentHash, &payload, &ts); err != nil {
			rows.Close()
			return err
		}
		manifest = append(manifest, ManifestEntry{BlobID: blobID, Hash: contentHash})

		f, err := zipWriter.Create(fmt.Sprintf("blobs/%s.json", blobID))
		if err != nil {
			rows.Close()
			return err
		}
		_, _ = f.Write([]byte(payload))
	}
	rows.Close()

	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	manifestFile, err := zipWriter.Create("manifest.json")
	if err != nil {
		return err
	}
	_, _ = manifestFile.Write(manifestBytes)

	// 2. Export Audit Chain (GoBD-konform komplettieren)
	chainRows, err := e.pool.Query(ctx, `
        SELECT id, tenant_id, action, actor, resource_id, payload::text, prev_hash, current_hash, created_at
        FROM evidence_audit_chain WHERE tenant_id = $1 ORDER BY id ASC
    `, tenantID)
	if err != nil {
		return err
	}

	var auditEntries []AuditChainExportEntry
	for chainRows.Next() {
		var entry AuditChainExportEntry
		var payloadRaw string
		if err := chainRows.Scan(&entry.ID, &entry.TenantID, &entry.Action, &entry.Actor, &entry.ResourceID, &payloadRaw, &entry.PrevHash, &entry.CurrentHash, &entry.CreatedAt); err != nil {
			chainRows.Close()
			return err
		}
		entry.Payload = json.RawMessage(payloadRaw)
		auditEntries = append(auditEntries, entry)
	}
	chainRows.Close()

	auditBytes, _ := json.MarshalIndent(auditEntries, "", "  ")
	auditFile, err := zipWriter.Create("audit_chain.json")
	if err != nil {
		return err
	}
	_, _ = auditFile.Write(auditBytes)

	return nil
}
