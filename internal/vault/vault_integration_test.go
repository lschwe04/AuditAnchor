package vault_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auditanchor/internal/audit"
	"auditanchor/internal/audit/auth"
	"auditanchor/internal/db"
	"auditanchor/internal/evidence"
	"auditanchor/internal/handlers"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const testJWTSecret = "super-secret-test-jwt-key-min-32-bytes-long!!!"
const testHMACSecret = "super-secret-test-hmac-key-min-32-bytes-long!!!"

func TestVault_EndToEnd_SecurityAndIngest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	t.Setenv("JWT_SECRET", testJWTSecret)
	t.Setenv("HMAC_TIMESTAMP_SECRET", testHMACSecret)

	// 1. Setup Testcontainers (PostgreSQL + Redis)
	pgURL, cleanupPG := setupPostgresContainer(t, ctx)
	defer cleanupPG()

	redisClient, cleanupRedis := setupRedisContainer(t, ctx)
	defer cleanupRedis()

	// 2. Initialize DB Pool & Apply Schema Migration 08
	dbPool, err := db.InitDB(ctx, pgURL)
	if err != nil {
		Fatalf(t, "db init failed: %v", err)
	}
	defer dbPool.Close()

	applyMigration08(ctx, t, dbPool)

	// 3. Initialize Vault Services & Handler Chain
	rateLimiter := auth.NewRedisRateLimiter(redisClient, 5, time.Minute)
	auditLogger := audit.NewLogger(dbPool)
	tsService := evidence.NewTimestampService(testHMACSecret)
	exporter := evidence.NewExporter(dbPool)

	mux := http.NewServeMux()
	vaultChain := func(next http.Handler) http.Handler {
		return auth.RedisRateLimitMiddleware(rateLimiter, true, auth.TenantAuthMiddleware(next))
	}

	ingestHandler := handlers.NewIngestHandler(dbPool, auditLogger, tsService)
	exportHandler := handlers.NewExportHandler(exporter, auditLogger)

	mux.Handle("/api/v1/evidence/ingest", vaultChain(http.HandlerFunc(ingestHandler.Ingest)))
	mux.Handle("/api/v1/evidence/export", vaultChain(http.HandlerFunc(exportHandler.Export)))

	// 4. Test Cases
	tenantA := "tenant-alpha"
	tenantB := "tenant-beta"
	tokenA := generateSignedJWT(tenantA, "auditor", time.Hour)
	tokenB := generateSignedJWT(tenantB, "auditor", time.Hour)

	t.Run("Security: Missing Auth should return 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/ingest", strings.NewReader(`{"payload":{"test":1}}`))
		req.Header.Set("X-Tenant-ID", tenantA)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assertStatus(t, rec.Code, http.StatusUnauthorized)
	})

	t.Run("Security: Tenant Mismatch should return 403", func(t *testing.T) {
		body := `{"payload":{"data":"secret"}}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/ingest", strings.NewReader(body))
		req.Header.Set("X-Tenant-ID", tenantB)
		req.Header.Set("Authorization", "Bearer "+tokenA)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assertStatus(t, rec.Code, http.StatusForbidden)
	})

	t.Run("HappyPath: Ingest valid evidence for tenant-alpha", func(t *testing.T) {
		body := `{"payload":{"event":"gobd_login_success","user":"admin"}}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/ingest", strings.NewReader(body))
		req.Header.Set("X-Tenant-ID", tenantA)
		req.Header.Set("Authorization", "Bearer "+tokenA)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assertStatus(t, rec.Code, http.StatusCreated)

		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["blob_id"] == "" || resp["hash"] == "" {
			t.Fatalf("expected blob_id and hash in response, got %v", resp)
		}
	})

	t.Run("Isolation: Tenant-beta cannot export tenant-alpha data", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/export?tenant_id="+tenantA, nil)
		req.Header.Set("X-Tenant-ID", tenantB)
		req.Header.Set("Authorization", "Bearer "+tokenB)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assertStatus(t, rec.Code, http.StatusForbidden)
	})

	t.Run("HappyPath: Export ZIP bundle for tenant-alpha", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/export", nil)
		req.Header.Set("X-Tenant-ID", tenantA)
		req.Header.Set("Authorization", "Bearer "+tokenA)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assertStatus(t, rec.Code, http.StatusOK)
		if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
			t.Fatalf("expected application/zip, got %s", ct)
		}
		if len(rec.Body.Bytes()) == 0 {
			t.Fatalf("expected ZIP payload, got empty body")
		}
	})
}

// --- Hilfsfunktionen für Test-Setup & Crypto ---

func setupPostgresContainer(t *testing.T, ctx context.Context) (string, func()) {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		Env:          map[string]string{"POSTGRES_PASSWORD": "secretpassword", "POSTGRES_DB": "auditanchor_test"},
		ExposedPorts: []string{"5432/tcp"},
		WaitingFor:   wait.ForListeningPort("5432/tcp").WithStartupTimeout(30 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432")
	connStr := fmt.Sprintf("postgres://postgres:secretpassword@%s:%s/auditanchor_test?sslmode=disable", host, port)

	return connStr, func() { _ = container.Terminate(ctx) }
}

func setupRedisContainer(t *testing.T, ctx context.Context) (*redis.Client, func()) {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp").WithStartupTimeout(30 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start redis container: %v", err)
	}

	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "6379")
	client := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%s", host, port)})

	return client, func() {
		_ = client.Close()
		_ = container.Terminate(ctx)
	}
}

func applyMigration08(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	schema := `
	CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
	CREATE TABLE IF NOT EXISTS evidence_blobs (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		blob_id VARCHAR(64) NOT NULL UNIQUE,
		tenant_id VARCHAR(64) NOT NULL,
		content_hash CHAR(64) NOT NULL,
		payload_json JSONB NOT NULL,
		timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
		hmac_sig CHAR(128) NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS evidence_audit_chain (
		id BIGSERIAL PRIMARY KEY,
		tenant_id VARCHAR(64) NOT NULL,
		action VARCHAR(64) NOT NULL,
		actor VARCHAR(128) NOT NULL,
		resource_id VARCHAR(128) NOT NULL,
		payload JSONB NOT NULL,
		prev_hash CHAR(64) NOT NULL,
		current_hash CHAR(64) NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE NOT NULL
	);
	`
	if _, err := pool.Exec(ctx, schema); err != nil {
		t.Fatalf("failed to apply migration 08: %v", err)
	}
}

func generateSignedJWT(tenantID, role string, ttl time.Duration) string {
	headerJSON, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claims := map[string]any{
		"tenant_id": tenantID,
		"role":      role,
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(ttl).Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	h := hmac.New(sha256.New, []byte(testJWTSecret))
	h.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return unsigned + "." + sig
}

func assertStatus(t *testing.T, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("expected HTTP status %d, got %d", want, got)
	}
}

func Fatalf(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Fatalf(format, args...)
}
