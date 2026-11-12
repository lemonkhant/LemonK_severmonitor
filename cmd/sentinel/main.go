package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lemonkhant/LemonK_severmonitor/internal/admin"
	"github.com/lemonkhant/LemonK_severmonitor/internal/httpapi"
	"github.com/lemonkhant/LemonK_severmonitor/internal/inventory"
	"github.com/lemonkhant/LemonK_severmonitor/internal/source"
	"github.com/lemonkhant/LemonK_severmonitor/internal/sshcollector"
	"github.com/lemonkhant/LemonK_severmonitor/internal/threat"
)

func main() {
	inventoryPath := setting("MONITOR_INVENTORY", "data/inventory.json")
	registry, err := inventory.Open(inventoryPath)
	if err != nil {
		log.Fatal(err)
	}
	telemetry, err := source.NewLive(registry)
	if err != nil {
		log.Fatal(err)
	}
	agent, err := os.ReadFile(setting("MONITOR_AGENT_CONFIG", "config/agent-linux.yaml"))
	if err != nil {
		log.Fatal(err)
	}

	dir := setting("MONITOR_WEB_ROOT", "web/dist")
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		log.Fatal("dashboard build is missing; build web/dist or use Docker Compose")
	}

	gate, err := admin.New(setting("SENTINEL_ADMIN_USER", "admin"), os.Getenv("SENTINEL_ADMIN_PASSWORD_FILE"), os.Getenv("SENTINEL_REQUIRE_AUTH") == "1", os.Getenv("SENTINEL_SECURE_COOKIES") == "1")
	if err != nil {
		log.Fatal(err)
	}
	sshDir := os.Getenv("SENTINEL_SSH_DIR")
	if sshDir != "" && !gate.Enabled() {
		log.Fatal("host SSH requires admin sign-in")
	}
	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	manager := sshcollector.New(stop, sshDir)

	securityStore, err := threat.Open(filepath.Join(filepath.Dir(inventoryPath), "threat.json"))
	if err != nil {
		log.Fatal(err)
	}
	security := threat.New(securityStore, telemetry, registry)
	go security.Run(stop)

	server := &http.Server{
		Addr:              setting("MONITOR_ADDR", "127.0.0.1:8080"),
		Handler:           gate.Protect(httpapi.New(telemetry, http.FileServer(http.Dir(dir)), registry, string(agent), manager, security)),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serve := make(chan error, 1)
	go func() { serve <- server.ListenAndServe() }()
	log.Printf("lemonK listening on %s", server.Addr)

	select {
	case err := <-serve:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case <-stop.Done():
		ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
			_ = server.Close()
		}
	}
}

func setting(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
