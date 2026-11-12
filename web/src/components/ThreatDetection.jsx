import { useEffect, useState } from 'react';
import { Badge, Empty, PanelTitle, Search } from './dashboard.jsx';
import { dateTime, severityTone } from '../presentation.js';

const areas = ['SIEM', 'Threat Intelligence', 'Detection Studio', 'Exposure Analytics', 'SOAR', 'UEBA'];
const endpoint = '/api/threat';
const initialRule = { name: '', contains: '', threshold: 5, severity: 'Medium', enabled: true };

function useThreatReport(range, refreshed) {
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        const response = await fetch(endpoint + '/report?range=' + encodeURIComponent(range), { signal: controller.signal });
        if (!response.ok) throw new Error();
        const data = await response.json();
        if (!controller.signal.aborted) {
          setReport({ range, data });
          setError('');
        }
      } catch {
        if (!controller.signal.aborted) setError('Unable to load threat detection data.');
      }
    }
    load();
    return () => controller.abort();
  }, [range, refreshed, revision]);

  return { report: report?.range === range ? report.data : null, error, reload: () => setRevision(value => value + 1) };
}

export function ThreatDetection({ range, provider, refreshed, showLogs }) {
  const [area, setArea] = useState('SIEM');
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState('');
  const { report, error, reload } = useThreatReport(range, refreshed);

  async function mutate(path, method, data) {
    setBusy(true);
    setMutationError('');
    try {
      const response = await fetch(endpoint + path, {
        method,
        ...(data == null ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }),
      });
      if (!response.ok) {
        const problem = await response.json().catch(() => null);
        throw new Error(problem?.error || 'Unable to save the change.');
      }
      reload();
      return true;
    } catch (failure) {
      setMutationError(failure.message);
      return false;
    } finally {
      setBusy(false);
    }
  }

  const exposures = report?.exposure ?? [];
  const names = new Map(exposures.map(({ asset }) => [asset.id, asset.name]));
  const selected = new Set(exposures.filter(({ asset }) => !provider || asset.provider === provider).map(({ asset }) => asset.id));
  const detections = (report?.detections ?? []).filter(row => selected.has(row.host));
  const cases = (report?.cases ?? []).filter(row => !provider || selected.has(row.detection.host));
  const caseIDs = new Set(cases.map(row => row.detection.id));
  const name = id => names.get(id) ?? id;
  const open = id => mutate('/cases/' + id + '?range=' + encodeURIComponent(range), 'POST');

  return <>
    <div className="threat-nav" aria-label="Threat detection areas">{areas.map(label =>
      <button key={label} type="button" aria-pressed={area === label} onClick={() => { setArea(label); setMutationError(''); }}>{label}</button>
    )}</div>
    {(error || mutationError) && <p className="notice" role="alert">{mutationError || error}</p>}
    {!report && !error && <div className="card loading" role="status">Loading security events…</div>}
    {report && <>
      {report.caseLimitReached && <p className="notice" role="status">Case storage is full. New cases cannot be opened.</p>}
      {area === 'SIEM' && <SIEM report={report} selected={selected} detections={detections} name={name} showLogs={showLogs} caseIDs={caseIDs} open={open} busy={busy} />}
      {area === 'Threat Intelligence' && <Intelligence report={report} detections={detections} name={name} caseIDs={caseIDs} open={open} busy={busy} mutate={mutate} />}
      {area === 'Detection Studio' && <Studio rules={report.rules} busy={busy} mutate={mutate} />}
      {area === 'Exposure Analytics' && <Exposure rows={exposures.filter(row => selected.has(row.asset.id))} />}
      {area === 'SOAR' && <Cases cases={cases} name={name} busy={busy} mutate={mutate} />}
      {area === 'UEBA' && <section className="card panel">
        <PanelTitle title="SSH behavior" subtitle="Flags a new source IP after three observed successful sign-ins for the same server and user in the selected window." />
        <Findings detections={detections.filter(row => row.kind === 'ssh-new-source')} name={name} caseIDs={caseIDs} open={open} busy={busy} />
      </section>}
    </>}
  </>;
}

function SIEM({ report, selected, detections, name, showLogs, caseIDs, open, busy }) {
  const [query, setQuery] = useState('');
  const logCount = report.exposure.reduce((count, row) => count + (selected.has(row.asset.id) ? row.logs : 0), 0);
  const match = query.trim().toLowerCase();
  const matching = detections.filter(row => [row.title, row.ip, row.user, row.evidence, name(row.host)].some(value => value?.toLowerCase().includes(match)));
  return <>
    <div className="threat-sources">
      <Badge text={report.logsAvailable ? (logCount ? logCount + ' log events in scope' : 'No log events in scope') : 'Loki unavailable or no servers registered'} tone={logCount ? 'green' : 'gray'} />
      <Badge text={report.alertsAvailable ? 'Wazuh alerts connected' : 'Wazuh alerts unavailable'} tone={report.alertsAvailable ? 'green' : 'gray'} />
      <button type="button" className="text-button" onClick={() => showLogs('')}>Open log explorer</button>
    </div>
    <section className="card panel">
      <PanelTitle title="Security findings" subtitle="Evaluates up to 200 recent Loki events and 200 Wazuh alerts in the selected time range.">
        <Search label="Search findings" value={query} change={setQuery} />
      </PanelTitle>
      <Findings detections={matching} name={name} caseIDs={caseIDs} open={open} busy={busy} />
    </section>
  </>;
}

function Findings({ detections, name, caseIDs, open, busy }) {
  if (!detections.length) return <Empty>No findings in the available data for this selection.</Empty>;
  return <div className="table-scroll"><table className="threat-table"><thead><tr><th>Finding</th><th>Server</th><th>Severity</th><th>Events</th><th>Latest event</th><th>Case</th></tr></thead>
    <tbody>{detections.map(item => <tr key={item.id}>
      <td><details><summary>{item.title}</summary>
        <p className="threat-evidence">{[item.technique, item.ip, item.user].filter(Boolean).join(' · ')}</p>
        <p className="threat-evidence">{item.evidence}</p>
      </details></td>
      <td>{name(item.host)}</td><td><Badge text={item.severity} tone={severityTone[item.severity]} /></td><td>{item.count}</td><td>{dateTime(item.time)}</td>
      <td>{caseIDs.has(item.id) ? <Badge text="Case created" tone="blue" /> : <button type="button" className="text-button" disabled={busy} onClick={() => open(item.id)}>Open case</button>}</td>
    </tr>)}</tbody>
  </table></div>;
}

function Intelligence({ report, detections, name, caseIDs, open, busy, mutate }) {
  async function add(event) {
    event.preventDefault();
    const form = event.currentTarget;
    if (await mutate('/indicators', 'POST', Object.fromEntries(new FormData(form)))) form.reset();
  }
  return <>
    <section className="card panel">
      <PanelTitle title="IP watchlist" subtitle="Add indicators from your own intelligence sources. lemonK matches them against observed SSH source addresses." />
      <form className="server-form" onSubmit={add}>
        <label>IP address<input name="ip" required maxLength={45} placeholder="IPv4 or IPv6 address" /></label>
        <label>Label<input name="label" required maxLength={100} /></label>
        <div><button className="primary" disabled={busy}>Add indicator</button></div>
      </form>
      {report.indicators.length > 0 && <div className="table-scroll"><table><thead><tr><th>IP address</th><th>Label</th><th>Action</th></tr></thead>
        <tbody>{report.indicators.map(item => <tr key={item.ip}><td>{item.ip}</td><td>{item.label}</td>
          <td><button type="button" className="text-button" disabled={busy} onClick={() => mutate('/indicators/' + encodeURIComponent(item.ip), 'DELETE')}>Remove</button></td>
        </tr>)}</tbody>
      </table></div>}
    </section>
    <section className="card panel"><PanelTitle title="Indicator matches" />
      <Findings detections={detections.filter(row => row.kind === 'ssh-watchlist')} name={name} caseIDs={caseIDs} open={open} busy={busy} />
    </section>
  </>;
}

function Studio({ rules, busy, mutate }) {
  const [draft, setDraft] = useState(initialRule);
  const change = (key, value) => setDraft(current => ({ ...current, [key]: value }));
  const rulePath = id => '/rules/' + encodeURIComponent(id);
  async function save(event) {
    event.preventDefault();
    if (await mutate(draft.id ? rulePath(draft.id) : '/rules', draft.id ? 'PUT' : 'POST', draft)) setDraft(initialRule);
  }
  return <section className="card panel">
    <PanelTitle title="Detection rules" subtitle="Custom rules match log text case-insensitively and count events per server in five-minute UTC buckets." />
    <form className="server-form" onSubmit={save}>
      <label>Rule name<input required maxLength={80} value={draft.name} onChange={e => change('name', e.target.value)} /></label>
      <label>Log text<input required maxLength={160} value={draft.contains} onChange={e => change('contains', e.target.value)} /></label>
      <label>Minimum matches<input type="number" min={1} max={50} required value={draft.threshold} onChange={e => change('threshold', Number(e.target.value))} /></label>
      <label>Severity<select value={draft.severity} onChange={e => change('severity', e.target.value)}>{['Low','Medium','High'].map(level => <option key={level}>{level}</option>)}</select></label>
      <div className="threat-actions"><button className="primary" disabled={busy}>{draft.id ? 'Save rule' : 'Create rule'}</button>
        {draft.id && <button type="button" className="text-button" onClick={() => setDraft(initialRule)}>Cancel</button>}</div>
    </form>
    <div className="table-scroll"><table><thead><tr><th>Rule</th><th>Severity</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody>{rules.map(rule => <tr key={rule.id}>
        <td><strong>{rule.name}</strong>{rule.contains && <small className="threat-evidence">{rule.threshold} × {rule.contains}</small>}</td>
        <td><Badge text={rule.severity} tone={severityTone[rule.severity]} /></td>
        <td><Badge text={rule.enabled ? 'Enabled' : 'Paused'} tone={rule.enabled ? 'green' : 'gray'} /></td>
        <td>{rule.builtIn ? 'Built in' : <div className="threat-actions">
          <button type="button" className="text-button" disabled={busy} onClick={() => setDraft(rule)}>Edit</button>
          <button type="button" className="text-button" disabled={busy} onClick={() => mutate(rulePath(rule.id), 'PUT', { ...rule, enabled: !rule.enabled })}>{rule.enabled ? 'Pause' : 'Enable'}</button>
          <button type="button" className="text-button" disabled={busy} onClick={async () => { if (await mutate(rulePath(rule.id), 'DELETE') && draft.id === rule.id) setDraft(initialRule); }}>Delete</button>
        </div>}</td>
      </tr>)}</tbody>
    </table></div>
  </section>;
}

function Exposure({ rows }) {
  return <section className="card panel">
    <PanelTitle title="Asset exposure and coverage" subtitle="Uses registered addresses and observed logs. Reachability, open ports, and vulnerabilities require scan or cloud inventory data." />
    {rows.length ? <div className="table-scroll"><table><thead><tr><th>Server</th><th>Address</th><th>Address type</th><th>Log events</th><th>SSH auth events</th></tr></thead>
      <tbody>{rows.map(({ asset, addressType, logs, authEvents }) => <tr key={asset.id}>
        <td>{asset.name}</td><td>{asset.address || '—'}</td><td><Badge text={addressType} tone={addressType === 'Non-private IP' ? 'amber' : 'gray'} /></td>
        <td>{logs}</td><td>{authEvents}</td>
      </tr>)}</tbody>
    </table></div> : <Empty>No registered servers in scope.</Empty>}
  </section>;
}

function Cases({ cases, name, busy, mutate }) {
  const [active, setActive] = useState('');
  const item = cases.find(row => row.detection.id === active);
  async function update(event) {
    event.preventDefault();
    const form = event.currentTarget;
    if (await mutate('/cases/' + item.detection.id, 'PATCH', Object.fromEntries(new FormData(form)))) form.reset();
  }
  return <section className="card panel">
    <PanelTitle title="Response cases" subtitle="lemonK opens cases for recent high-severity findings. Review the evidence, record notes, and update the case status." />
    {cases.length ? <div className="table-scroll"><table><thead><tr><th>Finding</th><th>Server</th><th>Status</th><th>Updated</th></tr></thead>
      <tbody>{cases.map(row => <tr key={row.detection.id}>
        <td><button type="button" className="text-button" onClick={() => setActive(row.detection.id)}>{row.detection.title}</button></td><td>{name(row.detection.host)}</td>
        <td><Badge text={row.status} tone={row.status === 'Resolved' ? 'green' : 'blue'} /></td><td>{dateTime(row.history.at(-1)?.time)}</td>
      </tr>)}</tbody>
    </table></div> : <Empty>No cases in scope.</Empty>}
    {item && <div className="threat-case" key={item.detection.id + item.history.length}>
      <PanelTitle title={item.detection.title} subtitle={name(item.detection.host)} />
      <p className="threat-evidence">{item.detection.evidence}</p>
      <form className="server-form" onSubmit={update}>
        <label>Case status<select name="status" defaultValue={item.status}>{['Open','Investigating','Resolved'].map(status => <option key={status}>{status}</option>)}</select></label>
        <label>Investigation note<input name="note" maxLength={1000} /></label>
        <div><button className="primary" disabled={busy}>Save case</button></div>
      </form>
      <ol className="threat-history">{[...item.history].reverse().map((entry, i) => <li key={i}>
        <strong>{entry.status}</strong> · {entry.actor} · {dateTime(entry.time)}{entry.note && <p>{entry.note}</p>}
      </li>)}</ol>
    </div>}
  </section>;
}
