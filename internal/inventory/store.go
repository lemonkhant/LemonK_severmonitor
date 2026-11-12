package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
)

var (
	ErrConnection = errors.New("use an IP address or DNS hostname and a valid SSH username")
	dnsLabel      = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	sshUser       = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$`)
	ErrInvalid    = errors.New("use a server ID of 1–80 letters, digits, dots, dashes or underscores, and provide a name and provider")
	ErrExists     = errors.New("a server with that ID already exists")
	ErrMissing    = errors.New("server not found")
	ErrLimit      = errors.New("the registry is limited to 200 servers")
	idPattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$`)
)

// Store manages one registry file for a single lemonK instance.
type Store struct {
	mu     sync.RWMutex
	path   string
	assets []monitor.Asset
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, assets: []monitor.Asset{}}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &s.assets); err != nil {
			return nil, fmt.Errorf("decode inventory: %w", err)
		}
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) List() []monitor.Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]monitor.Asset{}, s.assets...)
}

func (s *Store) Add(asset monitor.Asset) (monitor.Asset, error) {
	asset.ID = strings.TrimSpace(asset.ID)
	asset.Name = strings.TrimSpace(asset.Name)
	asset.Provider = strings.TrimSpace(asset.Provider)
	asset.Region = strings.TrimSpace(asset.Region)
	if err := setConnection(&asset, asset.Address, asset.SSHUser); err != nil {
		return monitor.Asset{}, err
	}
	if !idPattern.MatchString(asset.ID) || len(asset.Name) == 0 || len(asset.Name) > 120 ||
		len(asset.Provider) == 0 || len(asset.Provider) > 80 || len(asset.Region) > 120 {
		return monitor.Asset{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.ContainsFunc(s.assets, func(existing monitor.Asset) bool { return existing.ID == asset.ID }) {
		return monitor.Asset{}, ErrExists
	}
	if len(s.assets) >= 200 {
		return monitor.Asset{}, ErrLimit
	}
	next := append(slices.Clone(s.assets), asset)
	if err := s.save(next); err != nil {
		return monitor.Asset{}, err
	}
	return asset, nil
}

func setConnection(asset *monitor.Asset, address, user string) error {
	address = strings.TrimSpace(address)
	user = strings.TrimSpace(user)
	if address != "" {
		ip, err := netip.ParseAddr(address)
		if err != nil {
			if len(address) > 253 {
				return ErrConnection
			}
			for _, label := range strings.Split(strings.TrimSuffix(address, "."), ".") {
				if !dnsLabel.MatchString(label) {
					return ErrConnection
				}
			}
		} else if ip.Zone() != "" {
			return ErrConnection
		}
	}
	if user != "" && !sshUser.MatchString(user) {
		return ErrConnection
	}
	asset.Address = address
	asset.SSHUser = user
	return nil
}

func (s *Store) UpdateConnection(id, address, user string) (monitor.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := slices.IndexFunc(s.assets, func(asset monitor.Asset) bool { return asset.ID == id })
	if index < 0 {
		return monitor.Asset{}, ErrMissing
	}
	next := slices.Clone(s.assets)
	if err := setConnection(&next[index], address, user); err != nil {
		return monitor.Asset{}, err
	}
	if err := s.save(next); err != nil {
		return monitor.Asset{}, err
	}
	return next[index], nil
}

func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := slices.IndexFunc(s.assets, func(asset monitor.Asset) bool { return asset.ID == id })
	if index < 0 {
		return ErrMissing
	}
	return s.save(slices.Delete(slices.Clone(s.assets), index, index+1))
}

func (s *Store) save(next []monitor.Asset) error {
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".inventory-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := json.NewEncoder(tmp).Encode(next); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	s.assets = next
	return nil
}
