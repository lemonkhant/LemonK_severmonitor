package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/lemonkhant/LemonK_severmonitor/internal/inventory"
	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
	"github.com/lemonkhant/LemonK_severmonitor/internal/sshcollector"
)

type Registry interface {
	List() []monitor.Asset
	Add(monitor.Asset) (monitor.Asset, error)
	Remove(string) error
	UpdateConnection(id, address, user string) (monitor.Asset, error)
}

func registerServers(mux *http.ServeMux, registry Registry, agentConfig string, sshManager *sshcollector.Manager) {
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, registry.List())
	})
	mux.HandleFunc("POST /api/servers", func(w http.ResponseWriter, r *http.Request) {
		if !localMutation(w, r) {
			return
		}
		var asset monitor.Asset
		if !readServerJSON(w, r, &asset) {
			return
		}
		asset, err := registry.Add(asset)
		if err != nil {
			registryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, asset)
	})
	mux.HandleFunc("PUT /api/servers/{id}/connection", func(w http.ResponseWriter, r *http.Request) {
		if !localMutation(w, r) {
			return
		}
		var connection struct {
			Address string `json:"address"`
			SSHUser string `json:"sshUser"`
		}
		if !readServerJSON(w, r, &connection) {
			return
		}
		if sshManager != nil {
			state := sshManager.Status(r.PathValue("id")).State
			if state == "running" || state == "connecting" || state == "disconnecting" {
				apiError(w, http.StatusConflict, "Disconnect SSH before changing the server address or username.")
				return
			}
		}
		asset, err := registry.UpdateConnection(r.PathValue("id"), connection.Address, connection.SSHUser)
		if err != nil {
			registryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, asset)
	})
	mux.HandleFunc("DELETE /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !localMutation(w, r) {
			return
		}
		if err := registry.Remove(r.PathValue("id")); err != nil {
			registryError(w, err)
			return
		}
		if sshManager != nil {
			sshManager.Forget(r.PathValue("id"))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/servers/{id}/agent.yaml", func(w http.ResponseWriter, r *http.Request) {
		for _, asset := range registry.List() {
			if asset.ID == r.PathValue("id") {
				config := strings.ReplaceAll(agentConfig, "${env:SENTINEL_HOST_ID}", asset.ID)
				w.Header().Set("Content-Type", "application/yaml")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Content-Disposition", "attachment; filename=sentinel-agent.yaml")
				_, _ = io.WriteString(w, config)
				return
			}
		}
		registryError(w, inventory.ErrMissing)
	})
}

func readServerJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	if media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); media != "application/json" {
		apiError(w, http.StatusUnsupportedMediaType, "send application/json")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil || decoder.Decode(new(any)) != io.EOF {
		apiError(w, http.StatusBadRequest, "invalid server details")
		return false
	}
	return true
}

func localMutation(w http.ResponseWriter, r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
			apiError(w, http.StatusForbidden, "cross-origin changes are disabled")
			return false
		}
	}
	return true
}

func registryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, inventory.ErrInvalid), errors.Is(err, inventory.ErrConnection):
		apiError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, inventory.ErrExists), errors.Is(err, inventory.ErrLimit):
		apiError(w, http.StatusConflict, err.Error())
	case errors.Is(err, inventory.ErrMissing):
		apiError(w, http.StatusNotFound, err.Error())
	default:
		log.Printf("server registry: %v", err)
		apiError(w, http.StatusInternalServerError, "could not save server registry")
	}
}

func apiError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("send JSON: %v", err)
	}
}
