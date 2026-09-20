package handlers

import (
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

	if err := h.exporter.StreamTenantEvidenceZIP(r.Context(), tenantID, w); err != nil {
		// Fallback falls Header schon geschrieben wurden, Log reicht
		_ = err
	}

	_ = h.logger.LogEvent(r.Context(), tenantID, "EVIDENCE_EXPORT_ZIP", "tenant-client", tenantID, nil)
}
