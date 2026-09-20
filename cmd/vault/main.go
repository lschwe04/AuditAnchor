package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auditanchor/internal/audit"
	"auditanchor/internal/audit/auth"
	"auditanchor/internal/db"
	"auditanchor/internal/evidence"
	"auditanchor/internal/handlers"

	"github.com/redis/go-redis/v9"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("Starte AuditAnchor Evidence-Vault MVP...")
	startupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbPool, err := db.InitDB(startupCtx, os.Getenv("DATABASE_URL"))
	if err != nil {
		slog.Error("DB Init fehlgeschlagen", "error", err)
		os.Exit(1)
	}
	defer dbPool.Close()

	var redisClient *redis.Client
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		if opts, err := redis.ParseURL(redisURL); err == nil {
			redisClient = redis.NewClient(opts)
		}
	}
	rateLimiter := auth.NewRedisRateLimiter(redisClient, 100, time.Minute)
	auditLogger := audit.NewLogger(dbPool)
	tsService := evidence.NewTimestampService(os.Getenv("HMAC_TIMESTAMP_SECRET"))
	exporter := evidence.NewExporter(dbPool)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	// Geschützte Vault-APIs (Tenant-Auth + Rate-Limiter)
	vaultChain := func(next http.Handler) http.Handler {
		return auth.RedisRateLimitMiddleware(rateLimiter, true, auth.TenantAuthMiddleware(next))
	}

	ingestHandler := handlers.NewIngestHandler(dbPool, auditLogger, tsService)
	exportHandler := handlers.NewExportHandler(exporter, auditLogger)

	mux.Handle("/api/v1/evidence/ingest", vaultChain(http.HandlerFunc(ingestHandler.Ingest)))
	mux.Handle("/api/v1/evidence/export", vaultChain(http.HandlerFunc(exportHandler.Export)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("AuditAnchor Vault HTTP-Listener aktiv", "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server abgestürzt", "error", err)
		}
	}()

	<-stop
	slog.Info("Vault wird heruntergefahren...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
}
