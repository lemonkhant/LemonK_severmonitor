package httpapi

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/lemonkhant/LemonK_severmonitor/internal/threat"
)

func registerThreat(mux *http.ServeMux, service *threat.Service) {
	mux.HandleFunc("GET /api/threat/report", func(w http.ResponseWriter, r *http.Request) {
		window, ok := threatWindow(w, r)
		if ok {
			writeJSON(w, http.StatusOK, service.Report(r.Context(), time.Now().UTC(), window))
		}
	})
	saveRule := func(w http.ResponseWriter, r *http.Request) {
		var rule threat.Rule
		if localMutation(w, r) && readServerJSON(w, r, &rule) {
			threatResult(w, service.Store.SaveRule(r.PathValue("id"), rule))
		}
	}
	mux.HandleFunc("POST /api/threat/rules", saveRule)
	mux.HandleFunc("PUT /api/threat/rules/{id}", saveRule)
	mux.HandleFunc("DELETE /api/threat/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		if localMutation(w, r) {
			threatResult(w, service.Store.DeleteRule(r.PathValue("id")))
		}
	})
	mux.HandleFunc("POST /api/threat/indicators", func(w http.ResponseWriter, r *http.Request) {
		var indicator threat.Indicator
		if localMutation(w, r) && readServerJSON(w, r, &indicator) {
			threatResult(w, service.Store.AddIndicator(indicator))
		}
	})
	mux.HandleFunc("DELETE /api/threat/indicators/{ip}", func(w http.ResponseWriter, r *http.Request) {
		if localMutation(w, r) {
			threatResult(w, service.Store.DeleteIndicator(r.PathValue("ip")))
		}
	})
	mux.HandleFunc("POST /api/threat/cases/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !localMutation(w, r) {
			return
		}
		window, ok := threatWindow(w, r)
		if ok {
			threatResult(w, service.OpenCase(r.Context(), r.PathValue("id"), time.Now().UTC(), window))
		}
	})
	mux.HandleFunc("PATCH /api/threat/cases/{id}", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Status string
			Note   string
		}
		if localMutation(w, r) && readServerJSON(w, r, &input) {
			threatResult(w, service.Store.UpdateCase(r.PathValue("id"), input.Status, input.Note, time.Now().UTC()))
		}
	})
}

func threatWindow(w http.ResponseWriter, r *http.Request) (time.Duration, bool) {
	window := r.URL.Query().Get("range")
	if window == "" {
		window = "6h"
	}
	duration, ok := ranges[window]
	if !ok {
		apiError(w, http.StatusBadRequest, "range must be 1h, 6h, or 24h")
	}
	return duration, ok
}

func threatResult(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, threat.ErrInput):
		apiError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, threat.ErrMissing):
		apiError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, threat.ErrConflict):
		apiError(w, http.StatusConflict, err.Error())
	default:
		log.Printf("security state: %v", err)
		apiError(w, http.StatusInternalServerError, "could not save security state")
	}
}
