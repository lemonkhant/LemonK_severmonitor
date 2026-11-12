import { useEffect, useState } from 'react';
import App from './App.jsx';
import { Icon } from './components/Icon.jsx';

export default function AdminGate() {
  const [session, setSession] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function checkSession() {
    const response = await fetch('/api/auth/session');
    if (!response.ok) throw new Error('lemonK could not check your session.');
    setSession(await response.json());
  }

  useEffect(() => {
    checkSession().catch(err => setError(err.message));
    const timer = setInterval(() => checkSession().catch(() => {}), 30000);
    return () => clearInterval(timer);
  }, []);

  async function signIn(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const credentials = Object.fromEntries(new FormData(form));
    setBusy(true);
    setError('');
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });
      form.elements.password.value = '';
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || 'Unable to sign in.');
      }
      await checkSession();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    const response = await fetch('/api/auth/logout', { method: 'POST' }).catch(() => null);
    if (response?.ok) {
      setError('');
      setSession({ required: true, signedIn: false });
    } else {
      setError('Could not sign out. Check the connection and try again.');
    }
  }

  if (session?.signedIn) {
    return <App signOut={session.required ? signOut : undefined} sessionError={error} />;
  }
  if (!session) {
    return <main className="admin-login"><p role={error ? 'alert' : 'status'}>{error || 'Checking lemonK session…'}</p></main>;
  }
  return <main className="admin-login">
    <form className="card admin-form" onSubmit={signIn}>
      <div className="admin-brand"><span className="brand-icon"><Icon name="pulse" size={23} /></span><h1>Sign in to lemonK</h1></div>
      <label>Username<input name="username" autoComplete="username" required /></label>
      <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
      {error && <p className="form-error" role="alert">{error}</p>}
      <button className="primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
    </form>
  </main>;
}
