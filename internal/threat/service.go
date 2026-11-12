package threat

import (
	"context"
	"log"
	"net/netip"
	"slices"
	"time"

	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
)

type Inventory interface {
	List() []monitor.Asset
}

type Service struct {
	Store     *Store
	source    EventSource
	inventory Inventory
}

func New(store *Store, source EventSource, inventory Inventory) *Service {
	return &Service{Store: store, source: source, inventory: inventory}
}

func (s *Service) Report(ctx context.Context, now time.Time, window time.Duration) Report {
	events := s.source.SecurityEvents(ctx, now, window)
	state := s.Store.snapshot()
	detections, authCounts := evaluate(events, state)
	logCounts := make(map[string]int)
	for _, entry := range events.Logs {
		logCounts[entry.Host]++
	}
	exposure := []Exposure{}
	for _, asset := range s.inventory.List() {
		exposure = append(exposure, Exposure{
			Asset: asset, AddressType: addressType(asset.Address), Logs: logCounts[asset.ID], AuthEvents: authCounts[asset.ID],
		})
	}
	slices.SortStableFunc(state.Cases, func(a, b Case) int {
		return lastUpdate(b).Compare(lastUpdate(a))
	})
	return Report{
		CaseLimitReached: len(state.Cases) >= caseLimit,
		LogsAvailable:    events.LogsAvailable, AlertsAvailable: events.AlertsAvailable, Detections: detections,
		Rules: append(slices.Clone(builtInRules), state.Rules...), Indicators: state.Indicators, Cases: state.Cases, Exposure: exposure,
	}
}

func addressType(address string) string {
	if address == "" {
		return "No address"
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return "Hostname"
	}
	ip = ip.Unmap()
	if ip.IsPrivate() || !ip.IsGlobalUnicast() {
		return "Private or local IP"
	}
	return "Non-private IP"
}

func (s *Service) OpenCase(ctx context.Context, id string, now time.Time, window time.Duration) error {
	if slices.ContainsFunc(s.Store.snapshot().Cases, func(item Case) bool { return item.Detection.ID == id }) {
		return nil
	}
	events := s.source.SecurityEvents(ctx, now, window)
	detections, _ := evaluate(events, s.Store.snapshot())
	for _, detection := range detections {
		if detection.ID == id {
			return s.Store.openCases([]Detection{detection}, "Admin", now)
		}
	}
	return ErrMissing
}

func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.scan(ctx, now.UTC())
		}
	}
}

func (s *Service) scan(ctx context.Context, now time.Time) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	events := s.source.SecurityEvents(ctx, now, time.Hour)
	detections, _ := evaluate(events, s.Store.snapshot())
	high := slices.DeleteFunc(detections, func(d Detection) bool {
		return d.Severity != "High" || d.Time.Before(now.Add(-10*time.Minute))
	})
	if ctx.Err() == nil {
		if err := s.Store.openCases(high, "Automation", now); err != nil {
			log.Printf("security case automation: %v", err)
		}
	}
}

func lastUpdate(item Case) time.Time {
	if len(item.History) == 0 {
		return item.Detection.Time
	}
	return item.History[len(item.History)-1].Time
}
