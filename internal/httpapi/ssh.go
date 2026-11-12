package httpapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/lemonkhant/LemonK_severmonitor/internal/sshcollector"
)

func registerSSH(mux *http.ServeMux, registry Registry, agentConfig string, manager *sshcollector.Manager) {
	mux.HandleFunc("GET /api/servers/{id}/ssh", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, manager.Status(r.PathValue("id")))
	})
	mux.HandleFunc("POST /api/servers/{id}/ssh", func(w http.ResponseWriter, r *http.Request) {
		if !localMutation(w, r) {
			return
		}
		for _, asset := range registry.List() {
			if asset.ID != r.PathValue("id") {
				continue
			}
			status, err := manager.Start(asset, agentConfig)
			switch {
			case err == nil:
				writeJSON(w, http.StatusAccepted, status)
			case errors.Is(err, sshcollector.ErrUnavailable):
				apiError(w, http.StatusServiceUnavailable, err.Error())
			case errors.Is(err, sshcollector.ErrInvalid), errors.Is(err, sshcollector.ErrKey):
				apiError(w, http.StatusBadRequest, err.Error())
			case errors.Is(err, sshcollector.ErrActive), errors.Is(err, sshcollector.ErrLimit):
				apiError(w, http.StatusConflict, err.Error())
			default:
				log.Printf("SSH start for %s: %v", asset.ID, err)
				apiError(w, http.StatusInternalServerError, "Could not start SSH on the lemonK host.")
			}
			return
		}
		apiError(w, http.StatusNotFound, "Server not found.")
	})
	mux.HandleFunc("DELETE /api/servers/{id}/ssh", func(w http.ResponseWriter, r *http.Request) {
		if !localMutation(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, manager.Stop(r.PathValue("id")))
	})
}
