const paths = {
  pulse: 'M2 12h5l3-7 4 14 3-7h5',
  grid: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  server: 'M3 4h18v6H3z M3 14h18v6H3z M7 7h.01 M7 17h.01 M11 7h6 M11 17h6',
  traffic: 'M8 3v16m-4-4 4 4 4-4m4 6V5m-4 4 4-4 4 4',
  logs: 'M6 3h9l4 4v14H6z M14 3v5h5 M9 12h7m-7 4h7',
  shield: 'M12 22c5-2 8-5.5 8-10V5l-8-3-8 3v7c0 4.5 3 8 8 10Z M12 8v5m0 3h.01',
  clock: 'M12 7v5l3 2 M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0Z',
  globe: 'M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0Z M2 12h20 M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20Z',
  arrow: 'M4 12h15m-6-6 6 6-6 6',
  chevron: 'm9 18 6-6-6-6',
  down: 'm6 9 6 6 6-6',
  refresh: 'M20 8a8 8 0 0 0-13-4L4 7m0-5v5h5m-5 9a8 8 0 0 0 13 4l3-3m0 5v-5h-5',
  search: 'M20 20l-4-4m2-5a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z',
  close: 'm6 6 12 12M18 6 6 18',
  check: 'm5 12 5 5L20 7',
  warning: 'M10 4a2.3 2.3 0 0 1 4 0l8 14a2 2 0 0 1-2 3H4a2 2 0 0 1-2-3Z M12 9v4m0 4h.01',
  link: 'M10 14a4 4 0 0 0 6 0l4-4a4 4 0 0 0-6-6l-2 2m2 4a4 4 0 0 0-6 0l-4 4a4 4 0 0 0 6 6l2-2',
};

export function Icon({ name, size = 18 }) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d={paths[name]} /></svg>;
}
