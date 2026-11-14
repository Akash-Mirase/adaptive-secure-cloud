import { useState } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth.js';
import { parseApiError } from '../utils/apiError.js';

export default function Login() {
  const { user, login, completeMfaLogin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from?.pathname || '/dashboard';

  const [form, setForm] = useState({ email: '', password: '' });
  const [mfaToken, setMfaToken] = useState(null);
  const [code, setCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  if (user) return <Navigate to="/dashboard" replace />;
  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      if (!mfaToken) {
        const r = await login(form.email, form.password);
        if (r.mfaRequired) { setMfaToken(r.mfaToken); return; }
      } else {
        await completeMfaLogin(mfaToken, useRecovery ? { recoveryCode: code } : { code }, form.password);
      }
      navigate(from, { replace: true });
    } catch (err) {
      setError(parseApiError(err).message);
    } finally {
      setSubmitting(false);
    }
  };

  const backToPassword = () => { setMfaToken(null); setCode(''); setError(''); setUseRecovery(false); };

  return (
    <div className="card shadow-sm">
      <div className="card-body p-4">
        <h2 className="h5 mb-3">{mfaToken ? 'Two-factor authentication' : 'Sign in'}</h2>
        {location.state?.registered && <div className="alert alert-success py-2 small">Account created. Please sign in.</div>}
        {error && <div className="alert alert-danger py-2 small" role="alert">{error}</div>}
        <form onSubmit={handleSubmit}>
          {!mfaToken ? (
            <>
              <div className="mb-3">
                <label className="form-label" htmlFor="email">Email</label>
                <input id="email" name="email" type="email" className="form-control" required autoComplete="username" value={form.email} onChange={handleChange} />
              </div>
              <div className="mb-3">
                <label className="form-label" htmlFor="password">Password</label>
                <input id="password" name="password" type="password" className="form-control" required autoComplete="current-password" value={form.password} onChange={handleChange} />
              </div>
            </>
          ) : (
            <div className="mb-3">
              <label className="form-label" htmlFor="code">{useRecovery ? 'Recovery code' : '6-digit code from your authenticator app'}</label>
              <input id="code" className="form-control font-monospace" required autoFocus autoComplete="one-time-code"
                inputMode={useRecovery ? 'text' : 'numeric'} value={code} onChange={(e) => setCode(e.target.value)} />
              <button type="button" className="btn btn-link btn-sm px-0" onClick={() => { setUseRecovery(!useRecovery); setCode(''); }}>
                {useRecovery ? 'Use authenticator code instead' : 'Use a recovery code instead'}
              </button>
            </div>
          )}
          <button className="btn btn-primary w-100" disabled={submitting}>{submitting ? 'Please wait...' : mfaToken ? 'Verify' : 'Sign in'}</button>
          {mfaToken && <button type="button" className="btn btn-link btn-sm w-100 mt-1" onClick={backToPassword}>Back</button>}
        </form>
        {!mfaToken && (
          <>
            <div className="text-center mt-3 small">No account? <Link to="/register">Register</Link></div>
            <div className="text-center mt-2 small"><Link to="/recover">Forgot your password?</Link></div>
          </>
        )}
      </div>
    </div>
  );
}