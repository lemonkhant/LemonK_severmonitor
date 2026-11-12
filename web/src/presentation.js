export const navigation = [['Overview', 'grid'], ['Fleet', 'server'], ['Servers', 'globe'], ['Traffic', 'traffic'], ['Logs', 'logs'], ['Alerts', 'shield'], ['Threat Detection', 'shield']];
export const descriptions = {
  Overview: 'Server health, network activity and security events across your infrastructure.',
  Servers: 'Register servers and download their agent configuration.',
  Fleet: 'Track the health and reporting status of your servers.',
  Traffic: 'Compare inbound and outbound throughput across your servers.',
  Logs: 'Search recent application and system events.',
  Alerts: 'Review suspicious activity and affected servers.',
  'Threat Detection': 'Investigate security findings, manage detections, and track response cases.',
};
export const rangeLabels = { '1h': 'Last 1 hour', '6h': 'Last 6 hours', '24h': 'Last 24 hours' };
export const fmtTime = (value) => value ? new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—';
export const dateTime = (value) => value ? new Date(value).toLocaleString() : 'Never';
export const percent = (value) => value == null ? '—' : Math.round(value) + '%';
export const rate = (value) => value == null ? '—' : new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value);
export const statusTone = { Healthy: 'green', Warning: 'amber', Stale: 'red', Unseen: 'gray', Unknown: 'gray', Reporting: 'blue' };
export const severityTone = { High: 'red', Medium: 'amber', Low: 'blue' };
