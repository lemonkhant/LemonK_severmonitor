package source

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Live struct {
	registry                 interface{ List() []monitor.Asset }
	metrics, logs, wazuh     string
	wazuhUser, wazuhPassword string
	client                   *http.Client
}

func NewLive(registry interface{ List() []monitor.Asset }) (*Live, error) {
	s := &Live{
		registry:  registry,
		metrics:   env("METRICS_URL", "http://victoriametrics:8428"),
		logs:      env("LOKI_URL", "http://loki:3100"),
		wazuh:     os.Getenv("WAZUH_URL"),
		wazuhUser: os.Getenv("WAZUH_USER"), wazuhPassword: os.Getenv("WAZUH_PASSWORD"),
	}
	for _, address := range []string{s.metrics, s.logs, s.wazuh} {
		if address == "" {
			continue
		}
		u, err := url.Parse(address)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("backend URLs must be HTTP or HTTPS without embedded credentials, query strings or fragments")
		}
	}
	if s.wazuh != "" && !strings.HasPrefix(s.wazuh, "https://") {
		return nil, fmt.Errorf("WAZUH_URL must use HTTPS")
	}
	if s.wazuh != "" && (s.wazuhUser == "" || s.wazuhPassword == "") {
		return nil, fmt.Errorf("set WAZUH_USER and WAZUH_PASSWORD to the dedicated alert reader")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caPath := os.Getenv("WAZUH_CA_FILE"); caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read Wazuh CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("Wazuh CA contains no certificates")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	s.client = &http.Client{
		Transport:     transport,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return s, nil
}

func (s *Live) json(ctx context.Context, method, endpoint string, values url.Values, body []byte, auth bool, result any) error {
	if len(values) > 0 {
		endpoint += "?" + values.Encode()
	}
	r, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if auth && s.wazuhUser != "" {
		r.SetBasicAuth(s.wazuhUser, s.wazuhPassword)
	}
	response, err := s.client.Do(r)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("backend returned HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(result)
}

func hostMatcher(assets []monitor.Asset) string {
	parts := make([]string, 0, len(assets))
	for _, a := range assets {
		parts = append(parts, regexp.QuoteMeta(a.ID))
	}
	return `host_id=~` + strconv.Quote(strings.Join(parts, "|"))
}

type queryResponse struct {
	Status string
	Data   struct {
		Result []struct {
			Metric map[string]string
			Value  []json.RawMessage
			Values [][]json.RawMessage
		}
	}
}

func (s *Live) metricQuery(ctx context.Context, path, expr string, extra url.Values) (queryResponse, error) {
	extra.Set("query", expr)
	var response queryResponse
	err := s.json(ctx, http.MethodGet, strings.TrimRight(s.metrics, "/")+path, extra, nil, false, &response)
	if err == nil && response.Status != "success" {
		err = fmt.Errorf("metrics query was rejected")
	}
	return response, err
}

func sample(pair []json.RawMessage) (float64, bool) {
	if len(pair) != 2 {
		return 0, false
	}
	var value string
	if err := json.Unmarshal(pair[1], &value); err != nil {
		return 0, false
	}
	n, err := strconv.ParseFloat(value, 64)
	return n, err == nil && !math.IsInf(n, 0) && !math.IsNaN(n)
}

func (s *Live) instant(ctx context.Context, expr string) (map[string]float64, error) {
	result, err := s.metricQuery(ctx, "/api/v1/query", expr, url.Values{})
	if err != nil {
		return nil, err
	}
	values := map[string]float64{}
	for _, row := range result.Data.Result {
		if n, ok := sample(row.Value); ok {
			values[row.Metric["host_id"]] = n
		}
	}
	return values, nil
}

func (s *Live) Snapshot(ctx context.Context, now time.Time, window time.Duration) monitor.Snapshot {
	d := emptySnapshot("live", now)
	assets := s.registry.List()
	if len(assets) == 0 {

		return d
	}
	filter := hostMatcher(assets)
	cpu := `system_cpu_time_seconds_total{` + filter
	mem := `system_memory_usage_bytes{` + filter
	disk := `system_filesystem_usage_bytes{` + filter + `,mountpoint="/"`
	expressions := []string{
		`100 * (1 - sum by(host_id)(rate(` + cpu + `,state="idle"}[5m])) / sum by(host_id)(rate(` + cpu + `}[5m])))`,
		`100 * sum by(host_id)(` + mem + `,state="used"}) / sum by(host_id)(` + mem + `})`,
		`100 * sum by(host_id)(` + disk + `,state="used"}) / sum by(host_id)(` + disk + `})`,
		`max by(host_id)(tlast_over_time(` + mem + `}[24h]))`,
	}
	var values [4]map[string]float64
	var errs [7]error
	var wg sync.WaitGroup
	for i, expr := range expressions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			values[i], errs[i] = s.instant(ctx, expr)
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		d.Logs, errs[4] = s.readLogs(ctx, now, window, assets)
	}()
	go func() {
		defer wg.Done()
		d.Traffic, errs[5] = s.readTraffic(ctx, now, window, assets)
	}()
	if s.wazuh != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Alerts, errs[6] = s.readAlerts(ctx, now, window, assets)
			d.AlertsConnected = errs[6] == nil
		}()
	}
	wg.Wait()

	if d.Logs == nil {
		d.Logs = []monitor.LogEntry{}
	}
	if d.Alerts == nil {
		d.Alerts = []monitor.Alert{}
	}
	if d.Traffic == nil {
		d.Traffic = []monitor.Traffic{}
	}
	for i, label := range []string{"CPU metrics", "memory metrics", "disk metrics", "host freshness", "log search", "network traffic", "security alerts"} {
		if errs[i] != nil {
			d.Warnings = append(d.Warnings, "Unable to load "+label+". Check the configured data source.")
		}
	}
	for _, asset := range assets {
		host := monitor.Host{Asset: asset, Status: "Unseen"}
		sec, exists := values[3][asset.ID]
		if errs[3] != nil {
			host.Status = "Unknown"
		} else if exists {
			seen := time.Unix(int64(sec), 0).UTC()
			host.Seen = &seen
			host.Status = "Stale"
			if now.Sub(seen) < 2*time.Minute {
				host.Status = "Reporting"
				for i, dest := range []**float64{&host.CPU, &host.Memory, &host.Disk} {
					if v, ok := values[i][asset.ID]; ok {
						*dest = number(math.Max(0, math.Min(100, v)))
					}
				}
				if host.CPU != nil && host.Memory != nil && host.Disk != nil {
					host.Status = "Healthy"
				}
				if (host.CPU != nil && *host.CPU >= 80) || (host.Memory != nil && *host.Memory >= 85) || (host.Disk != nil && *host.Disk >= 85) {
					host.Status = "Warning"
				}
			}
		}
		d.Hosts = append(d.Hosts, host)
	}
	return d
}

func (s *Live) readTraffic(ctx context.Context, now time.Time, window time.Duration, assets []monitor.Asset) ([]monitor.Traffic, error) {
	providers := map[string]string{}
	for _, asset := range assets {
		providers[asset.ID] = asset.Provider
	}
	expr := `sum by (host_id,direction) (rate(system_network_io_bytes_total{` + hostMatcher(assets) + `,device!="lo",direction=~"receive|transmit"}[5m])) * 8 / 1000000`
	result, err := s.metricQuery(ctx, "/api/v1/query_range", expr, url.Values{
		"start": {strconv.FormatInt(now.Add(-window).Unix(), 10)},
		"end":   {strconv.FormatInt(now.Unix(), 10)},
		"step":  {strconv.FormatInt(int64(window/time.Second)/36, 10)},
	})
	if err != nil {
		return nil, err
	}
	totals := map[string]map[int64]monitor.Point{}
	for _, row := range result.Data.Result {
		provider := providers[row.Metric["host_id"]]
		direction := row.Metric["direction"]
		if provider == "" || (direction != "receive" && direction != "transmit") {
			continue
		}
		if totals[provider] == nil {
			totals[provider] = map[int64]monitor.Point{}
		}
		for _, pair := range row.Values {
			rate, ok := sample(pair)
			if !ok {
				continue
			}
			var at float64
			if json.Unmarshal(pair[0], &at) != nil {
				continue
			}
			stamp := int64(at)
			point := totals[provider][stamp]
			point.Time = time.Unix(stamp, 0).UTC()
			dest := &point.RX
			if direction == "transmit" {
				dest = &point.TX
			}
			if *dest == nil {
				*dest = number(0)
			}
			**dest += rate
			totals[provider][stamp] = point
		}
	}
	var traffic []monitor.Traffic
	for provider, totals := range totals {
		t := monitor.Traffic{Provider: provider}
		for _, point := range totals {
			t.Points = append(t.Points, point)
		}
		sort.Slice(t.Points, func(i, j int) bool { return t.Points[i].Time.Before(t.Points[j].Time) })
		traffic = append(traffic, t)
	}
	sort.Slice(traffic, func(i, j int) bool { return traffic[i].Provider < traffic[j].Provider })
	return traffic, nil
}

func (s *Live) readLogs(ctx context.Context, now time.Time, window time.Duration, assets []monitor.Asset) ([]monitor.LogEntry, error) {
	var response struct {
		Status string
		Data   struct {
			Result []struct {
				Stream map[string]string
				Values [][]json.RawMessage
			}
		}
	}
	// Loki's index selector narrows to named services. host_id is structured metadata.
	expr := `{service_name=~".+"} | ` + hostMatcher(assets)
	err := s.json(ctx, http.MethodGet, strings.TrimRight(s.logs, "/")+"/loki/api/v1/query_range", url.Values{
		"query":     {expr},
		"start":     {strconv.FormatInt(now.Add(-window).UnixNano(), 10)},
		"end":       {strconv.FormatInt(now.UnixNano(), 10)},
		"limit":     {"200"},
		"direction": {"backward"},
	}, nil, false, &response)
	if err != nil {
		return nil, err
	}
	if response.Status != "success" {
		return nil, fmt.Errorf("log query was rejected")
	}
	allowed := map[string]bool{}
	for _, a := range assets {
		allowed[a.ID] = true
	}
	var logs []monitor.LogEntry
	for _, group := range response.Data.Result {
		for _, row := range group.Values {
			if len(row) < 2 {
				continue
			}
			var stamp, line string
			if json.Unmarshal(row[0], &stamp) != nil || json.Unmarshal(row[1], &line) != nil {
				continue
			}
			at, err := strconv.ParseInt(stamp, 10, 64)
			if err != nil {
				continue
			}
			host, level := group.Stream["host_id"], group.Stream["severity_text"]
			if len(row) >= 3 {
				var meta map[string]string
				if json.Unmarshal(row[2], &meta) == nil {
					if meta["host_id"] != "" {
						host = meta["host_id"]
					}
					if meta["severity_text"] != "" {
						level = meta["severity_text"]
					}
				}
			}
			if !allowed[host] {
				continue
			}
			var parsed struct {
				Level   string
				Message string
			}
			if json.Unmarshal([]byte(line), &parsed) == nil {
				if parsed.Level != "" && level == "" {
					level = parsed.Level
				}
				if parsed.Message != "" {
					line = parsed.Message
				}
			}
			logs = append(logs, monitor.LogEntry{Time: time.Unix(0, at).UTC(), Host: host, Service: group.Stream["service_name"], Level: strings.ToLower(level), Message: line})
		}
	}
	sort.Slice(logs, func(i, j int) bool { return logs[i].Time.After(logs[j].Time) })
	return logs, nil
}

func (s *Live) readAlerts(ctx context.Context, now time.Time, window time.Duration, assets []monitor.Asset) ([]monitor.Alert, error) {
	names := make([]string, 0, len(assets))
	for _, a := range assets {
		names = append(names, a.ID)
	}
	body, err := json.Marshal(map[string]any{
		"size":    100,
		"sort":    []any{map[string]string{"timestamp": "desc"}},
		"_source": []string{"agent.name", "rule.level", "rule.description", "timestamp"},
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"terms": map[string]any{"agent.name": names}},
			map[string]any{"range": map[string]any{"timestamp": map[string]string{
				"gte": now.Add(-window).Format(time.RFC3339), "lte": now.Format(time.RFC3339),
			}}},
		}}},
	})
	if err != nil {
		return nil, err
	}
	var response struct {
		Hits struct {
			Hits []struct {
				ID     string `json:"_id"`
				Index  string `json:"_index"`
				Source struct {
					Timestamp string
					Agent     struct{ Name string }
					Rule      struct {
						Level       int
						Description string
					}
				} `json:"_source"`
			}
		}
	}
	err = s.json(ctx, http.MethodPost, strings.TrimRight(s.wazuh, "/")+"/wazuh-alerts-*/_search", nil, body, true, &response)
	if err != nil {
		return nil, err
	}
	var alerts []monitor.Alert
	for _, hit := range response.Hits.Hits {
		var stamp time.Time
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
			if t, err := time.Parse(layout, hit.Source.Timestamp); err == nil {
				stamp = t.UTC()
				break
			}
		}
		if stamp.IsZero() {
			continue
		}
		severity := "Low"
		switch {
		case hit.Source.Rule.Level >= 12:
			severity = "High"
		case hit.Source.Rule.Level >= 7:
			severity = "Medium"
		}
		alerts = append(alerts, monitor.Alert{
			ID: hit.Index + ":" + hit.ID, Host: hit.Source.Agent.Name, Time: stamp,
			Title: hit.Source.Rule.Description, Severity: severity,
			Detail: fmt.Sprintf("Wazuh rule level %d.", hit.Source.Rule.Level),
		})
	}
	return alerts, nil
}
