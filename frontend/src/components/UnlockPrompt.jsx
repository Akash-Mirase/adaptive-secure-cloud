import { useState } from 'react';
import { useAuth } from '../hooks/useAuth.js';

export default function UnlockPrompt() {
  const { unlockWithPassword, logout } = useAuth();
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await unlockWithPassword(password);
    } catch (err) {
      setError(err.message || 'Could not unlock your keys.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="d-flex align-items-center justify-content-center py-5">
      <div className="card shadow-sm" style={{ maxWidth: 420, width: '100%' }}>
        <div className="card-body p-4">
          <h2 className="h5">Unlock your files</h2>
          <p className="small text-muted">
            Your session is signed in, but your encryption keys are locked in this tab.
            Enter your password to unlock them (this never leaves your browser).
          </p>
          {error && <div className="alert alert-danger py-2 small">{error}</div>}
          <form onSubmit={handleSubmit}>
            <input
              type="password" className="form-control mb-3" placeholder="Password"
              autoComplete="current-password" value={password}
              onChange={(e) => setPassword(e.target.value)} required
            />
            <button className="btn btn-primary w-100 mb-2" disabled={busy}>{busy ? 'Unlocking...' : 'Unlock'}</button>
          </form>
          <button className="btn btn-link btn-sm w-100" onClick={logout}>Sign out instead</button>
        </div>
      </div>
    </div>
  );
}