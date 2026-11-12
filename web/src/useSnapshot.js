import { useEffect, useState } from 'react';

export function useSnapshot(range) {
  const [snapshot, setSnapshot] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [reload, setReload] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    async function refresh() {
      if (pending) return;
      pending = true;
      setBusy(true);
      try {
        const response = await fetch('/api/snapshot?range=' + encodeURIComponent(range), { signal: controller.signal });
        if (!response.ok) throw new Error('Dashboard request failed');
        const data = await response.json();
        if (!controller.signal.aborted) {
          setSnapshot(data);
          setError('');
        }
      } catch (e) {
        if (e.name !== 'AbortError') setError('Unable to reach the monitoring API.');
      } finally {
        pending = false;
        if (!controller.signal.aborted) setBusy(false);
      }
    }
    refresh();
    const timer = setInterval(refresh, 30000);
    return () => { controller.abort(); clearInterval(timer); };
  }, [range, reload]);

  return { snapshot, busy, error, refresh: () => setReload(value => value + 1) };
}
