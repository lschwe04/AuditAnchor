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

	startStr, endStr := "N/A", "N/A"
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

	limit := 1000

	// 1. Export Evidence Blobs via Paginierung & JSON Streaming
	manifestFile, err := zipWriter.Create("manifest.json")
	if err != nil {
		return fmt.Errorf("failed to create manifest.json in zip: %w", err)
	}
	_, _ = manifestFile.Write([]byte("[\n"))

	offsetBlobs := 0
	firstBlob := true

	for {
		rows, err := e.pool.Query(ctx, `
			SELECT blob_id, content_hash, payload_json::text, timestamp 
			FROM evidence_blobs WHERE tenant_id = $1 
			ORDER BY timestamp ASC LIMIT $2 OFFSET $3
		`, tenantID, limit, offsetBlobs)
		if err != nil {
			return fmt.Errorf("failed to query evidence blobs (offset %d): %w", offsetBlobs, err)
		}

		var count int
		for rows.Next() {
			count++
			var blobID, contentHash, payload string
			var ts time.Time
			if err := rows.Scan(&blobID, &contentHash, &payload, &ts); err != nil {
				rows.Close()
				return fmt.Errorf("scan error on evidence blob: %w", err)
			}

			// Blob Datei in ZIP anlegen
			f, err := zipWriter.Create(fmt.Sprintf("blobs/%s.json", blobID))
			if err != nil {
				rows.Close()
				return fmt.Errorf("failed to create zip entry for blob %s: %w", blobID, err)
			}
			_, _ = f.Write([]byte(payload))

			// Manifest im Stream ergänzen
			if !firstBlob {
				_, _ = manifestFile.Write([]byte(",\n"))
			}
			firstBlob = false
			entryBytes, _ := json.Marshal(ManifestEntry{BlobID: blobID, Hash: contentHash})
			_, _ = manifestFile.Write(entryBytes)
		}
		rows.Close()

		if count < limit {
			break // Letzte Seite erreicht
		}
		offsetBlobs += limit
	}
	_, _ = manifestFile.Write([]byte("\n]"))

	// 2. Export Audit Chain via Paginierung & JSON Streaming
	auditFile, err := zipWriter.Create("audit_chain.json")
	if err != nil {
		return fmt.Errorf("failed to create audit_chain.json in zip: %w", err)
	}
	_, _ = auditFile.Write([]byte("[\n"))

	offsetAudit := 0
	firstAudit := true

	for {
		chainRows, err := e.pool.Query(ctx, `
			SELECT id, tenant_id, action, actor, resource_id, payload::text, prev_hash, current_hash, created_at
			FROM evidence_audit_chain WHERE tenant_id = $1 
			ORDER BY id ASC LIMIT $2 OFFSET $3
		`, tenantID, limit, offsetAudit)
		if err != nil {
			return fmt.Errorf("failed to query audit chain (offset %d): %w", offsetAudit, err)
		}

		var count int
		for chainRows.Next() {
			count++
			var entry AuditChainExportEntry
			var payloadRaw string
			if err := chainRows.Scan(&entry.ID, &entry.TenantID, &entry.Action, &entry.Actor, &entry.ResourceID, &payloadRaw, &entry.PrevHash, &entry.CurrentHash, &entry.CreatedAt); err != nil {
				chainRows.Close()
				return fmt.Errorf("scan error on audit chain: %w", err)
			}
			entry.Payload = json.RawMessage(payloadRaw)

			if !firstAudit {
				_, _ = auditFile.Write([]byte(",\n"))
			}
			firstAudit = false
			entryBytes, _ := json.Marshal(entry)
			_, _ = auditFile.Write(entryBytes)
		}
		chainRows.Close()

		if count < limit {
			break // Letzte Seite erreicht
		}
		offsetAudit += limit
	}
	_, _ = auditFile.Write([]byte("\n]"))

	return nil
}
