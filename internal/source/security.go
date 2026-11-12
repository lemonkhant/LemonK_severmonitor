package source

import (
	"context"
	"sync"
	"time"

	"github.com/lemonkhant/LemonK_severmonitor/internal/threat"
)

// SecurityEvents queries the same sources used by Logs and Alerts without fetching host metrics.
func (s *Live) SecurityEvents(ctx context.Context, now time.Time, window time.Duration) threat.Events {
	var events threat.Events
	assets := s.registry.List()
	if len(assets) == 0 {
		return events
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logs, err := s.readLogs(ctx, now, window, assets)
		events.Logs, events.LogsAvailable = logs, err == nil
	}()
	if s.wazuh != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			alerts, err := s.readAlerts(ctx, now, window, assets)
			events.Alerts, events.AlertsAvailable = alerts, err == nil
		}()
	}
	wg.Wait()
	return events
}
