package httpapi

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
	"github.com/lemonkhant/LemonK_severmonitor/internal/sshcollector"
	"github.com/lemonkhant/LemonK_severmonitor/internal/threat"
)

var ranges = map[string]time.Duration{
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
}

// New serves the monitoring API and its same-origin frontend.
func New(source monitor.Source, frontend http.Handler, registry Registry, agentConfig string, sshManager *sshcollector.Manager, security *threat.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		window := r.URL.Query().Get("range")
		if window == "" {
			window = "6h"
		}
		duration, ok := ranges[window]
		if !ok {
			http.Error(w, "range must be 1h, 6h, or 24h", http.StatusBadRequest)
			return
		}
		snapshot := source.Snapshot(r.Context(), time.Now().UTC(), duration)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			log.Printf("send snapshot: %v", err)
		}
	})
	if registry != nil {
		registerServers(mux, registry, agentConfig, sshManager)
		if sshManager != nil {
			registerSSH(mux, registry, agentConfig, sshManager)
		}
	}
	if security != nil {
		registerThreat(mux, security)
	}
	mux.HandleFunc("GET /api/", http.NotFound)
	mux.Handle("GET /", frontend)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, r)
	})
}
