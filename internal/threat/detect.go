package threat

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
)

const correlationWindow = 5 * time.Minute

var sshEvent = regexp.MustCompile(`(?:^|\s)sshd(?:-session)?(?:\[\d+\])?: (Accepted|Failed) \S+ for (?:invalid user )?(\S+) from (\S+) port \d+`)

var builtInRules = []Rule{
	{ID: "ssh-brute-force", Name: "Repeated failed SSH sign-ins", Threshold: 5, Severity: "High", Enabled: true, BuiltIn: true},
	{ID: "ssh-new-source", Name: "SSH sign-in from a new source", Threshold: 3, Severity: "Medium", Enabled: true, BuiltIn: true},
	{ID: "ssh-watchlist", Name: "SSH source matches the IP watchlist", Threshold: 1, Severity: "High", Enabled: true, BuiltIn: true},
}

type authEvent struct {
	log      monitor.LogEntry
	user     string
	ip       string
	accepted bool
}

func parseAuth(entry monitor.LogEntry) (authEvent, bool) {
	message := entry.Message
	if entry.Service == "sshd" || entry.Service == "sshd-session" {
		message = entry.Service + ": " + message
	}
	match := sshEvent.FindStringSubmatch(message)
	if len(match) == 0 {
		return authEvent{}, false
	}
	ip, err := netip.ParseAddr(match[3])
	if err != nil || ip.Zone() != "" {
		return authEvent{}, false
	}
	return authEvent{log: entry, user: match[2], ip: ip.Unmap().String(), accepted: match[1] == "Accepted"}, true
}

func detectionID(parts ...string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(parts, "\x00"))))
}

type groupKey struct {
	rule   string
	host   string
	ip     string
	bucket time.Time
}

func addToGroup(groups map[groupKey]Detection, rule Rule, entry monitor.LogEntry, ip, user, technique string) {
	bucket := entry.Time.UTC().Truncate(correlationWindow)
	key := groupKey{rule: rule.ID, host: entry.Host, ip: ip, bucket: bucket}
	current := groups[key]
	if current.Count == 0 {
		current = Detection{
			ID: detectionID(rule.ID, entry.Host, ip, bucket.Format(time.RFC3339)), Kind: rule.ID,
			Title: rule.Name, Severity: rule.Severity, Host: entry.Host, IP: ip, User: user, Technique: technique,
		}
	}
	current.Count++
	current.Time = entry.Time
	current.Evidence = evidence(entry.Message)
	if current.User != user {
		current.User = ""
	}
	groups[key] = current
}

type baseline struct {
	samples   int
	addresses map[string]bool
}

func evaluate(events Events, config state) ([]Detection, map[string]int) {
	logs := slices.Clone(events.Logs)
	slices.SortStableFunc(logs, func(a, b monitor.LogEntry) int { return a.Time.Compare(b.Time) })
	thresholds := make(map[string]int)
	rules := make([]Rule, 0, len(config.Rules))
	for _, rule := range config.Rules {
		if rule.Enabled {
			rule.Contains = strings.ToLower(rule.Contains)
			rules = append(rules, rule)
			thresholds[rule.ID] = rule.Threshold
		}
	}
	thresholds[builtInRules[0].ID] = builtInRules[0].Threshold
	thresholds[builtInRules[2].ID] = 1
	indicators := make(map[string]string, len(config.Indicators))
	for _, indicator := range config.Indicators {
		indicators[indicator.IP] = indicator.Label
	}

	detections := []Detection{}
	authCounts := map[string]int{}
	groups := map[groupKey]Detection{}
	baselines := map[[2]string]*baseline{}
	seen := map[monitor.LogEntry]bool{}
	for _, entry := range logs {
		if seen[entry] {
			continue
		}
		seen[entry] = true
		message := strings.ToLower(entry.Message)
		for _, rule := range rules {
			if strings.Contains(message, rule.Contains) {
				addToGroup(groups, rule, entry, "", "", "")
			}
		}

		auth, ok := parseAuth(entry)
		if !ok {
			continue
		}
		authCounts[entry.Host]++
		if label, matched := indicators[auth.ip]; matched {
			rule := builtInRules[2]
			rule.Name += " (" + label + ")"
			addToGroup(groups, rule, entry, auth.ip, auth.user, "")
		}
		if !auth.accepted {
			addToGroup(groups, builtInRules[0], entry, auth.ip, auth.user, "T1110")
			continue
		}
		key := [2]string{entry.Host, auth.user}
		history := baselines[key]
		if history == nil {
			history = &baseline{addresses: map[string]bool{}}
			baselines[key] = history
		}
		if history.samples >= builtInRules[1].Threshold && !history.addresses[auth.ip] {
			rule := builtInRules[1]
			detections = append(detections, Detection{
				ID:   detectionID(rule.ID, entry.Host, auth.user, auth.ip, entry.Time.UTC().Format(time.RFC3339Nano)),
				Kind: rule.ID, Title: rule.Name, Severity: rule.Severity, Host: entry.Host, Time: entry.Time,
				IP: auth.ip, User: auth.user, Technique: "T1078", Count: 1, Evidence: evidence(entry.Message),
			})
		}
		history.addresses[auth.ip] = true
		history.samples++
	}

	for key, detection := range groups {
		if detection.Count >= thresholds[key.rule] {
			detections = append(detections, detection)
		}
	}
	for _, alert := range events.Alerts {
		detections = append(detections, Detection{
			ID: detectionID("wazuh", alert.ID), Kind: "wazuh", Title: alert.Title, Severity: alert.Severity,
			Host: alert.Host, Time: alert.Time, Count: 1, Evidence: alert.Detail,
		})
	}
	slices.SortFunc(detections, func(a, b Detection) int {
		if order := b.Time.Compare(a.Time); order != 0 {
			return order
		}
		return strings.Compare(a.ID, b.ID)
	})
	return detections, authCounts
}

func evidence(message string) string {
	const maxBytes = 1024
	if len(message) <= maxBytes {
		return message
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(message[end]) {
		end--
	}
	return message[:end] + "…"
}
