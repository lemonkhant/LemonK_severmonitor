import { useEffect, useState } from 'react';

const activeStates = new Set(['connecting', 'running', 'disconnecting']);
const labels = {
  connecting: 'Connecting over SSH…',
  running: 'SSH session running',
  disconnecting: 'Disconnecting…',
  disconnected: 'SSH disconnected',
  failed: 'SSH connection failed',
};

async function callSSH(id, method) {
  const response = await fetch('/api/servers/' + encodeURIComponent(id) + '/ssh', { method });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || 'Could not check the SSH connection.');
  return body;
}

export function SSHSetup({ server }) {
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    async function poll() {
      try {
        const data = await callSSH(server.id, 'GET');
        if (active) setStatus(data);
      } catch (err) {
        if (active) setError(err.message);
      }
    }
    poll();
    const timer = setInterval(poll, 3000);
    return () => { active = false; clearInterval(timer); };
  }, [server.id]);

  async function change(method) {
    setBusy(true);
    setError('');
    try {
      setStatus(await callSSH(server.id, method));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (!status) return <p role={error ? 'alert' : 'status'}>{error || 'Checking SSH setup…'}</p>;
  if (!status.enabled) return <p>Enable host SSH in the office deployment to connect from lemonK.</p>;
  if (!server.address || !server.sshUser) return <p>Use Edit connection to save the address and SSH username.</p>;

  const active = activeStates.has(status.state);
  return <div className="ssh-controls">
    <p>Connect as <strong>{server.sshUser}@{server.address}</strong> using the key configured on the lemonK host.</p>
    <p role="status">{labels[status.state] || 'Checking SSH…'}</p>
    {(error || status.message) && <p className="form-error" role="alert">{error || status.message}</p>}
    <button type="button" className={active ? 'text-button' : 'primary'}
      disabled={busy || status.state === 'disconnecting'} onClick={() => change(active ? 'DELETE' : 'POST')}>
      {active ? 'Disconnect SSH' : 'Connect over SSH'}
    </button>
    {status.state === 'running' && <p>Metrics appear in the dashboard when the collector reports.</p>}
  </div>;
}
