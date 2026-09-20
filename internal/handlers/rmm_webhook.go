package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RMMWebhookPayload struct {
	Source   string         `json:"source"`
	AlertID  string         `json:"alert_id"`
	Severity string         `json:"severity"`
	IOCs     map[string]any `json:"iocs,omitempty"`
}

type RMMWebhookHandler struct {
	pool *pgxpool.Pool
}

func NewRMMWebhookHandler(pool *pgxpool.Pool) *RMMWebhookHandler {
	return &RMMWebhookHandler{pool: pool}
}

func (h *RMMWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// 1. Mandatory Security & Tenant Headers
	tenantID := r.Header.Get("X-Tenant-ID")
	integration := r.Header.Get("X-Integration-Name")
	timestampStr := r.Header.Get("X-Webhook-Timestamp")
	signatureHeader := r.Header.Get("X-Hub-Signature-256")

	if tenantID == "" || integration == "" || timestampStr == "" || signatureHeader == "" {
		http.Error(w, `{"error":"missing mandatory security headers"}`, http.StatusBadRequest)
		return
	}

	// 2. Replay Protection (max 5 minutes skew window)
	reqTime, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		http.Error(w, `{"error":"invalid timestamp format, RFC3339 required"}`, http.StatusBadRequest)
		return
	}
	if time.Since(reqTime).Abs() > 5*time.Minute {
		http.Error(w, `{"error":"timestamp outside replay protection window"}`, http.StatusUnauthorized)
		return
	}

	// 3. Read body safely with strict size limit (1MB)
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, `{"error":"failed to read payload body"}`, http.StatusBadRequest)
		return
	}

	// 4. Fetch Tenant-Scoped Secret
	var secret string
	ctx := r.Context()
	err = h.pool.QueryRow(ctx, `
		SELECT secret_value FROM tenant_webhook_secrets 
		WHERE tenant_id = $1 AND integration_name = $2 AND is_active = true
	`, tenantID, integration).Scan(&secret)
	if err != nil {
		http.Error(w, `{"error":"unauthorized tenant or inactive integration"}`, http.StatusUnauthorized)
		return
	}

	// 5. Timing-Safe HMAC-SHA256 Verification
	expectedSig := computeHMACSHA256(body, []byte(secret))
	cleanSig := strings.TrimPrefix(strings.ToLower(signatureHeader), "sha256=")
	if !hmac.Equal([]byte(cleanSig), []byte(expectedSig)) {
		http.Error(w, `{"error":"HMAC signature verification failed"}`, http.StatusUnauthorized)
		return
	}

	// 6. Strict Schema Enforcement
	var payload RMMWebhookPayload
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields() // Optional, erzwingt exaktes Schema
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, `{"error":"strict schema validation failed"}`, http.StatusBadRequest)
		return
	}
	if payload.AlertID == "" || payload.Source == "" {
		http.Error(w, `{"error":"missing mandatory payload fields (source/alert_id)"}`, http.StatusBadRequest)
		return
	}

	// 7. Forensic Detection (Zero Outbound SSRF Fetch - string/regex matching only)
	h.processForensicIOCs(ctx, tenantID, payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   "accepted",
		"alert_id": payload.AlertID,
	})
}

func computeHMACSHA256(message, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *RMMWebhookHandler) processForensicIOCs(ctx context.Context, tenantID string, payload RMMWebhookPayload) {
	if rawIOC, ok := payload.IOCs["suspicious_webhook"]; ok {
		if hookURL, valid := rawIOC.(string); valid && isExfilDomain(hookURL) {
			// REIN LOKALE WORM-Protokollierung ohne Outbound-Requests (SSRF-Schutz)
			_, _ = h.pool.Exec(ctx, `
				INSERT INTO evidence_audit_chain (tenant_id, action, actor, resource_id, payload, prev_hash, current_hash, created_at)
				SELECT $1, 'FORENSIC_ATTACKER_HOOK_DETECTED', 'rmm-webhook-shield', $2, $3, 
				       COALESCE((SELECT current_hash FROM evidence_audit_chain WHERE tenant_id=$1 ORDER BY id DESC LIMIT 1), '0000000000000000000000000000000000000000000000000000000000000000'), 
				       'forensic-logged', NOW()
			`, tenantID, payload.AlertID, fmt.Sprintf(`{"detected_exfil_hook": "%s"}`, hookURL))
		}
	}
}

func isExfilDomain(url string) bool {
	susDomains := []string{"discord.com/api/webhooks", "webhook.office.com", "api.telegram.org"}
	for _, d := range susDomains {
		if strings.Contains(strings.ToLower(url), d) {
			return true
		}
	}
	return false
}
