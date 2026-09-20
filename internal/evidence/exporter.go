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

type Exporter struct {
	pool *pgxpool.Pool
}

func NewExporter(pool *pgxpool.Pool) *Exporter {
	return &Exporter{pool: pool}
}

func (e *Exporter) StreamTenantEvidenceZIP(ctx context.Context, tenantID string, w io.Writer) error {
	rows, err := e.pool.Query(ctx, `
        SELECT blob_id, content_hash, payload_json, timestamp 
        FROM evidence_blobs WHERE tenant_id = $1 ORDER BY id ASC
    `, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	var manifest []ManifestEntry

	for rows.Next() {
		var blobID, contentHash, payload string
		var ts time.Time
		if err := rows.Scan(&blobID, &contentHash, &payload, &ts); err != nil {
			return err
		}
		manifest = append(manifest, ManifestEntry{BlobID: blobID, Hash: contentHash})

		f, err := zipWriter.Create(fmt.Sprintf("blobs/%s.json", blobID))
		if err != nil {
			return err
		}
		_, _ = f.Write([]byte(payload))
	}

	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	manifestFile, err := zipWriter.Create("manifest.json")
	if err != nil {
		return err
	}
	_, _ = manifestFile.Write(manifestBytes)

	return nil
}
