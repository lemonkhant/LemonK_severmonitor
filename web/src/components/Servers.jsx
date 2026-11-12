import { useState } from 'react';
import { Badge, Empty, PanelTitle } from './dashboard.jsx';
import { statusTone } from '../presentation.js';
import { SSHSetup } from './SSHSetup.jsx';

const initial = { id: '', name: '', provider: 'Office', region: '', address: '', sshUser: '' };

async function changeServer(url, method, value) {
  const response = await fetch(url, {
    method,
    ...(value && { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) }),
  });
  if (response.ok) return response.status === 204 ? null : response.json();
  const result = await response.json().catch(() => ({}));
  throw new Error(result.error || 'Could not update the server registry.');
}

function agentURL(id) {
  return '/api/servers/' + encodeURIComponent(id) + '/agent.yaml';
}

export function Servers({ hosts, refresh }) {
  const [form, setForm] = useState(initial);
  const [enrolled, setEnrolled] = useState(null);
  const [connection, setConnection] = useState(null);
  const [remove, setRemove] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const field = key => ({
    value: form[key],
    onChange: event => setForm({ ...form, [key]: event.target.value }),
  });

  async function add(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      setEnrolled(await changeServer('/api/servers', 'POST', form));
      setForm(initial);
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function saveConnection(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      setEnrolled(await changeServer('/api/servers/' + encodeURIComponent(connection.id) + '/connection', 'PUT', {
        address: connection.address,
        sshUser: connection.sshUser,
      }));
      setConnection(null);
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function deleteServer() {
    setBusy(true);
    setError('');
    try {
      await changeServer('/api/servers/' + encodeURIComponent(remove.id), 'DELETE');
      if (enrolled?.id === remove.id) setEnrolled(null);
      setRemove(null);
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return <div className="server-admin">
    <section className="card panel">
      <PanelTitle title="Add a server" />
      <form className="server-form" onSubmit={add}>
        <label>IP address or hostname<input required maxLength={253} placeholder="192.0.2.10" {...field('address')} /></label>
        <label>SSH username <small>optional</small><input maxLength={64} placeholder="ubuntu" {...field('sshUser')} /></label>
        <label>Server name<input required maxLength={120} placeholder="Office web server" {...field('name')} /></label>
        <label>Server ID<input required maxLength={80} pattern="[a-zA-Z0-9][a-zA-Z0-9_.\\-]{0,79}" title="Letters, digits, dots, dashes or underscores" placeholder="office-web-01" {...field('id')} /></label>
        <label>Provider<select {...field('provider')}><option>Office</option><option>DigitalOcean</option><option>AWS</option><option>Other</option></select></label>
        <label>Location <small>optional</small><input maxLength={120} placeholder="Singapore" {...field('region')} /></label>
        <button className="primary" disabled={busy} type="submit">Add server</button>
      </form>
      {error && <p className="server-feedback" role="alert">{error}</p>}
      {enrolled && <div className="server-feedback" aria-live="polite">
        <strong>Set up {enrolled.name}</strong>

        <SSHSetup key={enrolled.id} server={enrolled} />
        <a href={agentURL(enrolled.id)}>Download Linux agent config for manual setup</a>
      </div>}
    </section>
    <section className="card panel">
      <PanelTitle title="Registered servers" subtitle="The agent must send telemetry before a server shows as reporting." />
      {hosts.length === 0 ? <Empty>Add your first server to get started.</Empty> :
        <div className="table-scroll"><table><thead><tr><th>Server</th><th>Address</th><th>Provider</th><th>Status</th><th>Agent config</th><th>Actions</th></tr></thead>
          <tbody>{hosts.map(host => <tr key={host.id}>
            <td>{host.name}<br /><small>{host.id}</small></td><td>{host.address || "—"}</td><td>{host.provider}</td>
            <td><Badge text={host.status === 'Unseen' ? 'Awaiting agent' : host.status} tone={statusTone[host.status]} /></td>
            <td><button type="button" className="text-button" onClick={() => setEnrolled(host)}>Setup</button></td>
            <td>{remove?.id === host.id ? <><button type="button" disabled={busy} onClick={deleteServer}>Confirm removal</button>{' '}<button type="button" disabled={busy} onClick={() => setRemove(null)}>Cancel</button></> : <>
              <button className="text-button" type="button" onClick={() => setConnection({ id: host.id, address: host.address || "", sshUser: host.sshUser || "" })}>Edit connection</button>{' '}
              <button className="text-button" type="button" onClick={() => setRemove(host)}>Remove</button>
            </>}</td>
          </tr>)}</tbody>
        </table></div>}
      {connection && <form className="server-form" onSubmit={saveConnection}>
        <label>Server address<input required value={connection.address} maxLength={253} onChange={event => setConnection({ ...connection, address: event.target.value })} /></label>
        <label>SSH username <small>optional</small><input value={connection.sshUser} maxLength={64} onChange={event => setConnection({ ...connection, sshUser: event.target.value })} /></label>
        <button className="primary" disabled={busy}>Save connection</button>
        <button className="text-button" type="button" onClick={() => setConnection(null)}>Cancel</button>
      </form>}
      {remove && <p className="server-feedback">Removing a server hides it from the dashboard. Stop its agent on the server to stop incoming telemetry.</p>}
    </section>
  </div>;
}
