import { useEffect, useRef } from 'react';
import { Icon } from './Icon.jsx';
import { fmtTime, dateTime, percent, statusTone, severityTone } from '../presentation.js';

export function Badge({ text, tone = 'gray' }) {
  return <span className={'badge ' + tone}><span />{text}</span>;
}

export function Provider({ value }) {
  const className = value === 'AWS' ? 'aws' : value === 'DigitalOcean' ? 'digitalocean' : 'office';
  return <span className="provider"><span className={'provider-dot ' + className} />{value}</span>;
}

export function PanelTitle({ title, subtitle, children }) {
  return <div className="panel-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{children}</div>;
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>;
}

export function Stat({ label, value, detail, icon, tone }) {
  return <div className="card stat"><div className="stat-top"><span>{label}</span><span className={'stat-icon ' + tone}><Icon name={icon} size={17} /></span></div><strong>{value}</strong><span className="stat-detail">{detail}</span></div>;
}

function Usage({ value, threshold }) {
  if (value == null) return <span className="muted">—</span>;
  return <span className="usage"><span className="usage-track"><span className={value >= threshold ? 'warm' : ''} style={{ width: value + '%' }} /></span>{percent(value)}</span>;
}

export function FleetTable({ hosts, open, compact }) {
  if (!hosts.length) return <Empty>No servers match the current filters.</Empty>;
  return <div className="table-scroll"><table><thead><tr><th>Server</th><th>Provider</th><th>Status</th><th>CPU</th><th>Memory</th><th>Disk</th>{!compact && <th>Last seen</th>}<th><span className="sr-only">Details</span></th></tr></thead>
    <tbody>{hosts.map(host => <tr key={host.id}>
      <td><button className="host-name" onClick={() => open(host)}><span className="host-icon"><Icon name="server" size={16} /></span><span><strong>{host.name}</strong><small>{host.region || host.id}</small></span></button></td>
      <td><Provider value={host.provider} /></td>
      <td><Badge text={host.status} tone={statusTone[host.status]} /></td>
      <td><Usage value={host.cpu} threshold={80} /></td><td><Usage value={host.memory} threshold={85} /></td><td><Usage value={host.disk} threshold={85} /></td>
      {!compact && <td className="muted">{fmtTime(host.seen)}</td>}
      <td><button className="icon-button row-button" aria-label={'Open ' + host.name} onClick={() => open(host)}><Icon name="chevron" size={15} /></button></td>
    </tr>)}</tbody></table></div>;
}

export function AlertList({ alerts, name, open }) {
  if (!alerts.length) return <Empty>No alerts match the current filters.</Empty>;
  return <div className="alert-list">{alerts.map(alert => <button className="alert-row" key={alert.id} onClick={() => open(alert)}>
    <span className={'alert-icon ' + severityTone[alert.severity]}><Icon name="shield" size={17} /></span>
    <span className="alert-copy"><strong>{alert.title}</strong><small>{name(alert.host)} · {fmtTime(alert.time)}</small></span>
    <Icon name="chevron" size={15} />
  </button>)}</div>;
}

export function Search({ value, change, label }) {
  return <label className="search"><Icon name="search" size={16} /><input aria-label={label} placeholder={label} value={value} onChange={event => change(event.target.value)} /></label>;
}

export function Filter({ icon, value, change, label, options }) {
  return <label className="filter"><Icon name={icon} size={16} /><select aria-label={label} value={value} onChange={event => change(event.target.value)}>
    {options.map(([id,text]) => <option key={id} value={id}>{text}</option>)}
  </select><Icon name="down" size={13} /></label>;
}

export function Drawer({ item, close, lookup, showLogs }) {
  const dialog = useRef(null);
  useEffect(() => {
    if (dialog.current && !dialog.current.open) dialog.current.showModal();
  }, []);
  const isHost = item.type === 'host';
  const data = item.data;
  return <dialog ref={dialog} className="drawer" onClose={close} onClick={event => { if (event.target === dialog.current) close(); }} aria-labelledby="drawer-title">
    <div className="drawer-body"><div className="drawer-top"><span className="stat-icon blue"><Icon name={isHost ? 'server' : 'shield'} /></span><button className="icon-button" aria-label="Close details" onClick={close}><Icon name="close" /></button></div>
      <h2 id="drawer-title">{isHost ? data.name : data.title}</h2>
      <Badge text={isHost ? data.status : data.severity} tone={isHost ? statusTone[data.status] : severityTone[data.severity]} />
      {isHost ? <dl className="details"><div><dt>Provider</dt><dd>{data.provider}</dd></div><div><dt>Region</dt><dd>{data.region || '—'}</dd></div><div><dt>Last seen</dt><dd>{dateTime(data.seen)}</dd></div><div><dt>CPU</dt><dd>{percent(data.cpu)}</dd></div><div><dt>Memory</dt><dd>{percent(data.memory)}</dd></div><div><dt>Root disk</dt><dd>{percent(data.disk)}</dd></div></dl> : <><dl className="details"><div><dt>Server</dt><dd>{lookup(data.host)}</dd></div><div><dt>Time</dt><dd>{dateTime(data.time)}</dd></div></dl><p className="alert-detail">{data.detail}</p></>}
      <button className="primary" onClick={() => showLogs(isHost ? data.id : data.host)}>View server logs <Icon name="arrow" size={17} /></button>
    </div>
  </dialog>;
}
