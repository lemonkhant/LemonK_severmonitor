import { useEffect, useRef, useState } from 'react';
import { fmtTime, rate } from '../presentation.js';
import { PanelTitle, Empty } from './dashboard.jsx';
import { Icon } from './Icon.jsx';

export function aggregateTraffic(groups) {
  const points = new Map();
  for (const group of groups) {
    for (const point of group.points) {
      const total = points.get(point.time) ?? { time: point.time, rx: null, tx: null };
      for (const field of ['rx', 'tx']) {
        if (point[field] != null) total[field] = (total[field] ?? 0) + point[field];
      }
      points.set(point.time, total);
    }
  }
  return [...points.values()].sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
}

function TrafficChart({ points }) {
  const ref = useRef(null);
  const [cursor, setCursor] = useState(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    function draw() {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (!width || !height) return;
      const dpr = window.devicePixelRatio || 1;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      const ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);
      const left = 46, right = width - 11, top = 10, bottom = height - 29;
      const plotW = right - left, plotH = bottom - top;
      const topValue = Math.max(0, ...points.flatMap(p => [p.rx ?? 0, p.tx ?? 0]));
      const unit = topValue > 4 ? Math.pow(10, Math.floor(Math.log10(topValue / 4))) : 0.25;
      const scale = Math.max(1, Math.ceil(topValue * 1.12 / (4 * unit)) * 4 * unit);
      const start = Date.parse(points[0].time);
      const span = Math.max(1, Date.parse(points.at(-1).time) - start);
      const xAt = (point) => left + (Date.parse(point.time) - start) / span * plotW;
      const yAt = (value) => bottom - value / scale * plotH;
      ctx.font = '11px Inter, system-ui, sans-serif';
      ctx.fillStyle = '#637088';
      ctx.textAlign = 'right';
      for (let i = 0; i <= 4; i++) {
        const y = top + plotH * i / 4;
        ctx.strokeStyle = '#e9edf4';
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(right, y); ctx.stroke();
        ctx.fillText(rate(scale * (1 - i / 4)), left - 9, y + 4);
      }
      const tickCount = width < 410 ? 3 : 6;
      for (let i = 0; i < tickCount; i++) {
        const p = i / (tickCount - 1);
        ctx.textAlign = i === 0 ? 'left' : i === tickCount - 1 ? 'right' : 'center';
        ctx.fillText(fmtTime(start + p * span), left + p * plotW, height - 6);
      }
      for (const [field, color] of [['rx', '#5144e9'], ['tx', '#24a48b']]) {
        const segments = [];
        let segment = [];
        for (const point of points) {
          if (point[field] == null) {
            if (segment.length) segments.push(segment);
            segment = [];
          } else {
            segment.push(point);
          }
        }
        if (segment.length) segments.push(segment);
        for (const group of segments) {
          ctx.beginPath();
          group.forEach((point, i) => i ? ctx.lineTo(xAt(point), yAt(point[field])) : ctx.moveTo(xAt(point), yAt(point[field])));
          ctx.strokeStyle = color; ctx.lineWidth = 2.4; ctx.lineJoin = 'round'; ctx.stroke();
          if (field === 'rx' && group.length > 1) {
            const gradient = ctx.createLinearGradient(0, top, 0, bottom);
            gradient.addColorStop(0, 'rgba(81,68,233,.19)');
            gradient.addColorStop(1, 'rgba(81,68,233,0)');
            ctx.lineTo(xAt(group.at(-1)), bottom); ctx.lineTo(xAt(group[0]), bottom);
            ctx.closePath(); ctx.fillStyle = gradient; ctx.fill();
          }
        }
      }
      if (cursor != null && points[cursor]) {
        const x = xAt(points[cursor]);
        ctx.strokeStyle = '#9ba5ba'; ctx.lineWidth = 1; ctx.setLineDash([4, 4]);
        ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, bottom); ctx.stroke(); ctx.setLineDash([]);
      }
    }
    const observer = new ResizeObserver(draw);
    observer.observe(canvas);
    draw();
    return () => observer.disconnect();
  }, [points, cursor]);

  if (!points.length) return <Empty>No network samples in this time range.</Empty>;
  const hovered = points[cursor];
  return <div className="chart-wrap">
    <canvas ref={ref} role="img" aria-label="Inbound and outbound server network throughput in megabits per second" onMouseMove={event => {
      const box = event.currentTarget.getBoundingClientRect();
      const progress = Math.min(1, Math.max(0, (event.clientX - box.left - 46) / (box.width - 57)));
      setCursor(Math.round(progress * (points.length - 1)));
    }} onMouseLeave={() => setCursor(null)} />
    {hovered && <div className="chart-tooltip">{fmtTime(hovered.time)} · {rate(hovered.rx)} in / {rate(hovered.tx)} out Mbps</div>}
  </div>;
}

export function TrafficPanel({ points, onOpen }) {
  return <section className="card panel traffic-panel">
    <PanelTitle title="Network traffic" subtitle="Server interfaces · Mbps">{onOpen && <button className="text-button" onClick={onOpen}>View traffic <Icon name="arrow" size={15} /></button>}</PanelTitle>
    <div className="chart-legend"><span><i className="inbound" />Inbound</span><span><i className="outbound" />Outbound</span></div>
    <TrafficChart points={points} />
  </section>;
}

export function FleetHealth({ hosts }) {
  const statuses = [['Healthy', '#24a48b'], ['Warning', '#f2a53b'], ['Stale', '#e56778'], ['Other', '#b8c1d5']];
  const counts = statuses.map(([name]) => name === 'Other' ? hosts.filter(h => !['Healthy', 'Warning', 'Stale'].includes(h.status)).length : hosts.filter(h => h.status === name).length);
  let position = 0;
  const segments = statuses.map(([,color],i) => {
    const from = position;
    position += hosts.length ? counts[i] / hosts.length * 100 : 0;
    return color + ' ' + from + '% ' + position + '%';
  });
  return <section className="card panel health-panel">
    <PanelTitle title="Fleet health" subtitle="Latest status by server" />
    <div className="health-body"><div className="donut" role="img" aria-label={statuses.map(([name], i) => name + ': ' + counts[i]).join(', ')} style={{ background: hosts.length ? 'conic-gradient(' + segments.join(',') + ')' : '#eef1f7' }}><div><strong>{hosts.length}</strong><span>servers</span></div></div>
      <div className="health-legend">{statuses.map(([name, color], i) => (i < 3 || counts[i] > 0) && <div key={name}><span><i style={{ background: color }} />{name}</span><strong>{counts[i]}</strong></div>)}</div>
    </div>
  </section>;
}
