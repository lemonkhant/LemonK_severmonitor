package sshcollector

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "embed"

	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
)

//go:embed remote.sh
var bootstrap string

const ready = "Starting the lemonK collector."

var (
	ErrUnavailable = errors.New("host SSH is disabled; configure the office SSH directory")
	ErrInvalid     = errors.New("save the server address and SSH username before connecting")
	ErrActive      = errors.New("this server already has an SSH connection")
	ErrLimit       = errors.New("the SSH connection limit has been reached")
	ErrKey         = errors.New("install the server's private key and verified known_hosts on the lemonK host")
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$`)
	userPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	hostPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
)

type Status struct {
	Enabled bool   `json:"enabled"`
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

type Manager struct {
	ctx  context.Context
	dir  string
	mu   sync.Mutex
	jobs map[string]*job
}

type job struct {
	cancel  context.CancelFunc
	output  *processOutput
	state   string
	message string
}

func New(ctx context.Context, dir string) *Manager {
	return &Manager{ctx: ctx, dir: dir, jobs: make(map[string]*job)}
}

func (m *Manager) Status(id string) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status(id)
}

func (m *Manager) status(id string) Status {
	s := Status{Enabled: m.dir != "", State: "disconnected"}
	if j := m.jobs[id]; j != nil {
		s.State, s.Message = j.state, j.message
		if s.State == "connecting" && j.output.started() {
			s.State = "running"
		}
	}
	return s
}

func (m *Manager) Start(asset monitor.Asset, agentConfig string) (Status, error) {
	if m.dir == "" {
		return Status{}, ErrUnavailable
	}
	if !idPattern.MatchString(asset.ID) || !userPattern.MatchString(asset.SSHUser) ||
		(net.ParseIP(asset.Address) == nil && !hostPattern.MatchString(asset.Address)) {
		return Status{}, ErrInvalid
	}
	key := filepath.Join(m.dir, asset.ID+".key")
	knownHosts := filepath.Join(m.dir, "known_hosts")
	if !regularFile(key) || !regularFile(knownHosts) {
		return Status{}, ErrKey
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing := m.jobs[asset.ID]; existing != nil && existing.cancel != nil {
		return Status{}, ErrActive
	}
	active := 0
	for _, j := range m.jobs {
		if j.cancel != nil {
			active++
		}
	}
	if active >= 16 {
		return Status{}, ErrLimit
	}
	ctx, cancel := context.WithCancel(m.ctx)
	j := &job{cancel: cancel, state: "connecting", output: &processOutput{}}

	config := strings.ReplaceAll(agentConfig, "${env:SENTINEL_HOST_ID}", asset.ID)
	payload := strings.NewReplacer("__SENTINEL_ID__", asset.ID, "__SENTINEL_CONFIG__", encode(config)).Replace(bootstrap)
	remote := "printf '%s' '" + encode(payload) + "' | base64 -d | bash"
	cmd := exec.CommandContext(ctx, "ssh", "-F", "/dev/null", "-tt",
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no",
		"-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile="+knownHosts, "-o", "ConnectTimeout=10",
		"-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=20", "-o", "ServerAliveCountMax=3",
		"-R", "127.0.0.1:14318:gateway:4318", "-i", key, "-l", asset.SSHUser, "--", asset.Address, remote)
	cmd.Stdout, cmd.Stderr = j.output, j.output
	cmd.WaitDelay = 3 * time.Second
	if err := cmd.Start(); err != nil {
		cancel()
		return Status{}, fmt.Errorf("start ssh: %w", err)
	}
	m.jobs[asset.ID] = j
	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()
		j.state = "disconnected"
		if ctx.Err() == nil && err != nil {
			j.state, j.message = "failed", j.output.failure()
		}
		j.cancel = nil
		cancel()
	}()
	return m.status(asset.ID), nil
}

func (m *Manager) Stop(id string) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j := m.jobs[id]; j != nil && j.cancel != nil {
		j.state = "disconnecting"
		j.cancel()
	}
	return m.status(id)
}

func (m *Manager) Forget(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j := m.jobs[id]; j != nil {
		if j.cancel != nil {
			j.cancel()
		}
		delete(m.jobs, id)
	}
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func encode(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

type processOutput struct {
	mu      sync.Mutex
	last    string
	running bool
}

var _ io.Writer = (*processOutput)(nil)

func (o *processOutput) Write(data []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.last += string(data)
	o.running = o.running || strings.Contains(o.last, ready)
	if len(o.last) > 8192 {
		o.last = o.last[len(o.last)-8192:]
	}
	return len(data), nil
}

func (o *processOutput) started() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.running
}

func (o *processOutput) failure() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	switch {
	case strings.Contains(o.last, "Host key verification failed"), strings.Contains(o.last, "REMOTE HOST IDENTIFICATION HAS CHANGED"):
		return "SSH host verification failed. Check the verified host key in known_hosts."
	case strings.Contains(o.last, "Permission denied"):
		return "SSH authentication failed. Check the username and the server key on the lemonK host."
	case strings.Contains(o.last, "remote port forwarding failed"):
		return "The server could not open the reverse tunnel on port 14318."
	case strings.Contains(o.last, "Connection refused"), strings.Contains(o.last, "Connection timed out"):
		return "The lemonK host could not reach the server over SSH."
	case strings.Contains(o.last, "curl:"), strings.Contains(o.last, "FAILED"):
		return "The remote collector download or checksum verification failed."
	default:
		return "The SSH session or Linux collector stopped. Check the target host and collector prerequisites."
	}
}
