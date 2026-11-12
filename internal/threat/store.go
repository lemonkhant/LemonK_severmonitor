package threat

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	ErrInput    = errors.New("invalid security settings")
	ErrMissing  = errors.New("security record not found")
	ErrConflict = errors.New("security record already exists or storage limit reached")
)

const caseLimit = 500

type state struct {
	Rules      []Rule      `json:"rules"`
	Indicators []Indicator `json:"indicators"`
	Cases      []Case      `json:"cases"`
}

type Store struct {
	mu   sync.Mutex
	path string
	data state
}

func Open(path string) (*Store, error) {
	store := &Store{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &store.data); err != nil {
		return nil, fmt.Errorf("decode security state: %w", err)
	}
	return store, nil
}

func (s *Store) snapshot() state {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.data)
}

func cloneState(data state) state {
	next := state{
		Rules:      append([]Rule{}, data.Rules...),
		Indicators: append([]Indicator{}, data.Indicators...),
		Cases:      append([]Case{}, data.Cases...),
	}
	for i := range next.Cases {
		next.Cases[i].History = slices.Clone(next.Cases[i].History)
	}
	return next
}

func (s *Store) update(change func(*state) (bool, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.data)
	changed, err := change(&next)
	if err != nil || !changed {
		return err
	}
	if err := s.write(next); err != nil {
		return err
	}
	s.data = next
	return nil
}

func (s *Store) write(next state) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".threat-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := json.NewEncoder(file).Encode(next); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), s.path)
}

func (s *Store) SaveRule(id string, rule Rule) error {
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Contains = strings.TrimSpace(rule.Contains)
	rule.ID = id
	rule.BuiltIn = false
	if rule.Name == "" || len(rule.Name) > 80 || rule.Contains == "" || len(rule.Contains) > 160 ||
		rule.Threshold < 1 || rule.Threshold > 50 || !validSeverity(rule.Severity) {
		return fmt.Errorf("%w: enter a rule name, search text, severity and a threshold from 1 to 50", ErrInput)
	}
	return s.update(func(data *state) (bool, error) {
		if id == "" {
			if len(data.Rules) >= 32 {
				return false, ErrConflict
			}
			key := make([]byte, 12)
			if _, err := rand.Read(key); err != nil {
				return false, err
			}
			rule.ID = "custom-" + hex.EncodeToString(key)
			data.Rules = append(data.Rules, rule)
			return true, nil
		}
		index := slices.IndexFunc(data.Rules, func(row Rule) bool { return row.ID == id })
		if index < 0 {
			return false, ErrMissing
		}
		data.Rules[index] = rule
		return true, nil
	})
}

func validSeverity(severity string) bool {
	return severity == "Low" || severity == "Medium" || severity == "High"
}

func (s *Store) DeleteRule(id string) error {
	return s.update(func(data *state) (bool, error) {
		index := slices.IndexFunc(data.Rules, func(row Rule) bool { return row.ID == id })
		if index < 0 {
			return false, ErrMissing
		}
		data.Rules = slices.Delete(data.Rules, index, index+1)
		return true, nil
	})
}

func (s *Store) AddIndicator(indicator Indicator) error {
	ip, err := netip.ParseAddr(strings.TrimSpace(indicator.IP))
	indicator.Label = strings.TrimSpace(indicator.Label)
	if err != nil || ip.Zone() != "" || indicator.Label == "" || len(indicator.Label) > 100 {
		return fmt.Errorf("%w: enter an IPv4 or IPv6 address and a label", ErrInput)
	}
	indicator.IP = ip.Unmap().String()
	return s.update(func(data *state) (bool, error) {
		if len(data.Indicators) >= 256 || slices.ContainsFunc(data.Indicators, func(row Indicator) bool { return row.IP == indicator.IP }) {
			return false, ErrConflict
		}
		data.Indicators = append(data.Indicators, indicator)
		return true, nil
	})
}

func (s *Store) DeleteIndicator(ip string) error {
	return s.update(func(data *state) (bool, error) {
		index := slices.IndexFunc(data.Indicators, func(row Indicator) bool { return row.IP == ip })
		if index < 0 {
			return false, ErrMissing
		}
		data.Indicators = slices.Delete(data.Indicators, index, index+1)
		return true, nil
	})
}

func (s *Store) openCases(detections []Detection, actor string, now time.Time) error {
	return s.update(func(data *state) (bool, error) {
		existing := make(map[string]bool, len(data.Cases))
		for _, item := range data.Cases {
			existing[item.Detection.ID] = true
		}
		changed := false
		for _, detection := range detections {
			if existing[detection.ID] {
				continue
			}
			if len(data.Cases) >= caseLimit {
				if actor == "Automation" {
					break
				}
				return false, ErrConflict
			}
			data.Cases = append(data.Cases, Case{
				Detection: detection, Status: "Open",
				History: []CaseEvent{{Time: now, Actor: actor, Status: "Open"}},
			})
			existing[detection.ID] = true
			changed = true
		}
		return changed, nil
	})
}

func (s *Store) UpdateCase(id, status, note string, now time.Time) error {
	note = strings.TrimSpace(note)
	if (status != "Open" && status != "Investigating" && status != "Resolved") || len(note) > 1000 {
		return fmt.Errorf("%w: select a case status and limit notes to 1,000 bytes", ErrInput)
	}
	return s.update(func(data *state) (bool, error) {
		index := slices.IndexFunc(data.Cases, func(row Case) bool { return row.Detection.ID == id })
		if index < 0 {
			return false, ErrMissing
		}
		item := &data.Cases[index]
		if item.Status == status && note == "" {
			return false, nil
		}
		if len(item.History) >= 25 {
			return false, ErrConflict
		}
		item.Status = status
		item.History = append(item.History, CaseEvent{Time: now, Actor: "Admin", Status: status, Note: note})
		return true, nil
	})
}
