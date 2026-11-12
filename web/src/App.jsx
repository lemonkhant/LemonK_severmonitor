import { ThreatDetection } from './components/ThreatDetection.jsx';
import { Servers } from './components/Servers.jsx';
import { useMemo, useState } from 'react';
import { Icon } from './components/Icon.jsx';
import { Badge, PanelTitle, Empty, Stat, FleetTable, AlertList, Search, Filter, Drawer } from './components/dashboard.jsx';
import { aggregateTraffic, TrafficPanel, FleetHealth } from './components/charts.jsx';
import { navigation, descriptions, rangeLabels, fmtTime, rate } from './presentation.js';
import { useSnapshot } from './useSnapshot.js';

export default function App({ signOut, sessionError }) {
  const [view, setView] = useState('Overview');
  const [range, setRange] = useState('6h');
  const [provider, setProvider] = useState('');
  const { snapshot, busy, error, refresh } = useSnapshot(range);
  const [hostSearch, setHostSearch] = useState('');
  const [logSearch, setLogSearch] = useState('');
  const [logHost, setLogHost] = useState('');
  const [severity, setSeverity] = useState('');
  const [drawer, setDrawer] = useState(null);

  const allHosts = snapshot?.hosts ?? [];
  const hosts = allHosts.filter(host => !provider || host.provider === provider);
  const ids = new Set(hosts.map(host => host.id));
  const name = id => allHosts.find(h => h.id === id)?.name ?? id;
  const alerts = (snapshot?.alerts ?? []).filter(alert => ids.has(alert.host));
  const logs = (snapshot?.logs ?? []).filter(log => ids.has(log.host) && (!logHost || logHost === log.host) &&
    [log.message, log.level, log.service, name(log.host)].some(value => value?.toLowerCase().includes(logSearch.trim().toLowerCase())));
  const points = useMemo(() => aggregateTraffic((snapshot?.traffic ?? []).filter(t => !provider || t.provider === provider)), [snapshot, provider]);
  const healthy = hosts.filter(h => h.status === 'Healthy').length;
  const peak = points.length ? Math.max(...points.map(point => (point.rx ?? 0) + (point.tx ?? 0))) : null;
  const providers = [...new Set(allHosts.map(h => h.provider))].sort();
  const openHost = data => setDrawer({ type: 'host', data });
  const openAlert = data => setDrawer({ type: 'alert', data });
  const showLogs = id => { setDrawer(null); setView('Logs'); setLogHost(id); setLogSearch(''); };

  return <div className="app">
    <aside className="sidebar">
      <a className="brand" aria-label="lemonK overview" href="#" onClick={event => { event.preventDefault(); setView('Overview'); }}><span className="brand-icon"><Icon name="pulse" size={23} /></span><span>lemonK</span></a>
      <div className="nav-label">Workspace</div>
      <nav aria-label="Dashboard">{navigation.map(([label, icon]) => <button key={label} className={view === label ? 'active' : ''} aria-current={view === label ? 'page' : undefined} onClick={() => setView(label)}><Icon name={icon} /><span>{label}</span></button>)}</nav>
      <div className="sidebar-bottom"><span className="workspace-icon"><Icon name="globe" size={17} /></span><span><strong>Infrastructure</strong><small>{'Live workspace'}</small></span></div>
    </aside>
    <div className="page">
      <header className="topbar"><div className="breadcrumb"><span className="breadcrumb-workspace">Workspace</span><span className="breadcrumb-brand">lemonK</span><Icon name="chevron" size={13} /> <strong>{view}</strong></div><div className="top-actions">
        {signOut && <button type="button" className="text-button" onClick={signOut}>Sign out</button>}
        {snapshot && <Badge text={'Live monitoring'} tone={'green'} />}
        <button className="icon-button refresh" aria-label="Refresh data" disabled={busy} onClick={refresh}><Icon name="refresh" size={17} /></button>
      </div></header>
      <main>
        {sessionError && <p className="form-error" role="alert">{sessionError}</p>}
        <div className="page-heading"><div><h1>{view === 'Overview' ? 'Infrastructure overview' : view}</h1><p>{descriptions[view]}</p></div>
          <div className="filters">
            <Filter icon="globe" label="Provider" value={provider} change={value => { setProvider(value); setLogHost(''); }} options={[[ '', 'All providers'], ...providers.map(p => [p,p])]} />
            <Filter icon="clock" label="Time range" value={range} change={setRange} options={Object.entries(rangeLabels)} />
          </div>
        </div>
        {error && <p className="notice" role="alert"><Icon name="warning" />{error}</p>}
        {snapshot?.warnings?.map(warning => <p className="notice" key={warning}><Icon name="warning" />{warning}</p>)}
        {!snapshot && !error && <div className="card loading" role="status">Loading monitoring data…</div>}
        {snapshot && view === 'Threat Detection' && <ThreatDetection range={range} provider={provider} refreshed={snapshot.updated} showLogs={showLogs} />}
        {snapshot && view === 'Servers' && <Servers hosts={allHosts} refresh={refresh} />}
        {snapshot && view === 'Overview' && allHosts.length === 0 && <section className="card panel"><PanelTitle title="Add your first server" subtitle="Register an office server, Droplet or EC2 instance to begin receiving live metrics." /><div className="server-feedback"><button className="primary" onClick={() => setView('Servers')}>Add server</button></div></section>}
        {snapshot && view === 'Overview' && allHosts.length > 0 && <>
          <div className="stats">
            <Stat label="Monitored servers" value={hosts.length} detail={new Set(hosts.map(h => h.provider)).size + ' locations'} icon="server" tone="blue" />
            <Stat label="Healthy servers" value={healthy} detail={hosts.length ? Math.round(healthy / hosts.length * 100) + '% of selected fleet' : 'No servers selected'} icon="pulse" tone="green" />
            <Stat label="Peak throughput" value={rate(peak)} detail="Mbps · inbound + outbound" icon="traffic" tone="blue" />
            <Stat label="Recent alerts" value={snapshot.alertsConnected ? alerts.length : '—'} detail={snapshot.alertsConnected ? alerts.filter(a => a.severity === 'High').length + ' high severity' : 'Alert source unavailable'} icon="shield" tone="amber" />
          </div>
          <div className="overview-grid">
            <TrafficPanel points={points} onOpen={() => setView('Traffic')} /><FleetHealth hosts={hosts} />
            <section className="card panel fleet-panel"><PanelTitle title="Server fleet" subtitle="Latest health across your servers"><button className="text-button" onClick={() => setView('Fleet')}>View fleet <Icon name="arrow" size={15} /></button></PanelTitle>
              <FleetTable hosts={hosts.slice(0,6)} open={openHost} compact />
            </section>
            <section className="card panel"><PanelTitle title="Recent alerts" subtitle={snapshot.alertsConnected ? 'Security and operational activity' : 'Alert source unavailable'} />
              <AlertList alerts={alerts.slice(0,4)} name={name} open={openAlert} />
              <button className="text-button alert-more" onClick={() => setView('Alerts')}>View all alerts <Icon name="arrow" size={15} /></button>
            </section>
          </div>
        </>}
        {snapshot && view === 'Fleet' && <section className="card panel"><PanelTitle title="Monitored servers" subtitle={hosts.length + ' servers in the selected providers'}><Search label="Search servers" value={hostSearch} change={setHostSearch} /></PanelTitle><FleetTable hosts={hosts.filter(h => [h.name,h.region,h.provider,h.status].some(s => s.toLowerCase().includes(hostSearch.toLowerCase())))} open={openHost} /></section>}
        {snapshot && view === 'Traffic' && <><TrafficPanel points={points} /><div className="traffic-breakdown">{snapshot.traffic.filter(t => !provider || t.provider === provider).map(group => <Stat key={group.provider} label={group.provider} value={rate(group.points.at(-1)?.rx)} detail="Latest inbound · Mbps" icon="traffic" tone="blue" />)}</div></>}
        {snapshot && view === 'Logs' && <section className="card panel">
          <PanelTitle title="Log explorer" subtitle="Search up to 200 recent events in the selected time range"><div className="filters"><Filter icon="server" label="Log server" value={logHost} change={setLogHost} options={[[ '', 'All servers'], ...hosts.map(h => [h.id,h.name])]} /><Search label="Search logs" value={logSearch} change={setLogSearch} /></div></PanelTitle>
          {logs.length ? <div className="table-scroll"><table className="log-table"><thead><tr><th>Time</th><th>Server</th><th>Service</th><th>Level</th><th>Message</th></tr></thead><tbody>{logs.map((log,i) => <tr key={log.time + i}><td>{fmtTime(log.time)}</td><td>{name(log.host)}</td><td>{log.service}</td><td><Badge text={log.level || 'Unknown'} tone={/error|fatal/i.test(log.level) ? 'red' : /warn/i.test(log.level) ? 'amber' : 'gray'} /></td><td className="log-message">{log.message}</td></tr>)}</tbody></table></div> : <Empty>No log events match the current filters.</Empty>}
        </section>}
        {snapshot && view === 'Alerts' && <section className="card panel"><PanelTitle title="Alert inbox" subtitle={snapshot.alertsConnected ? 'Most recent alerts for the selected time range' : 'Connect a Wazuh indexer to see security alerts'}><Filter icon="shield" label="Alert severity" value={severity} change={setSeverity} options={[[ '', 'All severities'], ['High','High'], ['Medium','Medium'], ['Low','Low']]} /></PanelTitle><AlertList alerts={alerts.filter(alert => !severity || alert.severity === severity)} name={name} open={openAlert} /></section>}
        {snapshot && <footer><span className="sync-dot" /> Updated {fmtTime(snapshot.updated)} <span>·</span> Refreshes every 30 seconds</footer>}
      </main>
    </div>
    {drawer && <Drawer item={drawer} close={() => setDrawer(null)} lookup={name} showLogs={showLogs} />}
  </div>;
}
