package handlers

import (
	"log/slog"
	"net/http"

	"auditanchor/internal/audit"
	"auditanchor/internal/audit/auth"
	"auditanchor/internal/evidence"
)

type ExportHandler struct {
	exporter *evidence.Exporter
	logger   *audit.Logger
}

func NewExportHandler(e *evidence.Exporter, l *audit.Logger) *ExportHandler {
	return &ExportHandler{exporter: e, logger: l}
}

func (h *ExportHandler) Export(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	tenantID, _ := r.Context().Value(auth.TenantKey).(string)
	targetTenant := r.URL.Query().Get("tenant_id")
	if targetTenant != "" && targetTenant != tenantID {
		http.Error(w, `{"error":"forbidden: scope mismatch"}`, http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="evidence-bundle.zip"`)

	// Streaming ausführen und Schreibfehler strukturiert loggen
	if err := h.exporter.StreamTenantEvidenceZIP(r.Context(), tenantID, w); err != nil {
		slog.Error("export stream failure mid-transfer",
			"tenant_id", tenantID,
			"error", err,
		)
		// Headers sind bereits geflasht, daher bricht der Stream ab; Audit bricht ebenfalls ab/wird error-geloggt
		_ = h.logger.LogEvent(r.Context(), tenantID, "EVIDENCE_EXPORT_FAILED", "tenant-client", tenantID, map[string]any{"error": err.Error()})
		return
	}

	if err := h.logger.LogEvent(r.Context(), tenantID, "EVIDENCE_EXPORT_ZIP", "tenant-client", tenantID, nil); err != nil {
		slog.Error("failed to write audit log for export", "tenant_id", tenantID, "error", err)
	}
}
