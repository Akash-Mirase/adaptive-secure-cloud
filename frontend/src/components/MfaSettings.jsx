import { useEffect, useState } from 'react';
import * as authService from '../services/authService.js';
import { parseApiError } from '../utils/apiError.js';

export default function MfaSettings() {
  const [status, setStatus] = useState(null);
  const [mode, setMode] = useState('idle'); // idle | password | scan | codes | disable | regen
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [enroll, setEnroll] = useState(null);
  const [codes, setCodes] = useState(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const refresh = () => authService.getMfaStatus().then(setStatus).catch((e) => setError(parseApiError(e).message));
  useEffect(() => { refresh(); }, []);

  const reset = () => { setMode('idle'); setPassword(''); setCode(''); setEnroll(null); setError(''); setSaved(false); };
  const run = (fn) => async (e) => {
    e.preventDefault(); setError(''); setBusy(true);
    try { await fn(); } catch (err) { setError(parseApiError(err).message); } finally { setBusy(false); }
  };

  const doEnroll = run(async () => { setEnroll(await authService.beginMfaEnrollment(password)); setPassword(''); setMode('scan'); });
  const doConfirm = run(async () => { const r = await authService.confirmMfaEnrollment(code); setCodes(r.recoveryCodes); setCode(''); setEnroll(null); setMode('codes'); await refresh(); });
  const doDisable = run(async () => { await authService.disableMfa({ password, code }); reset(); await refresh(); });
  const doRegen = run(async () => { const r = await authService.regenerateMfaCodes({ password, code }); setCodes(r.recoveryCodes); setPassword(''); setCode(''); setMode('codes'); await refresh(); });

  const codeInput = (
    <input className="form-control mb-2 font-monospace" placeholder="6-digit code" inputMode="numeric" autoComplete="one-time-code"
      value={code} onChange={(e) => setCode(e.target.value)} required aria-label="Authenticator code" />
  );
  const pwInput = (
    <input type="password" className="form-control mb-2" placeholder="Current password" autoComplete="current-password"
      value={password} onChange={(e) => setPassword(e.target.value)} required aria-label="Current password" />
  );

  return (
    <div className="card shadow-sm mt-3">
      <div className="card-header fw-semibold">Two-factor authentication</div>
      <div className="card-body">
        {error && <div className="alert alert-danger py-2 small" role="alert">{error}</div>}
        {!status && !error && <p className="text-muted small">Loading...</p>}

        {status && mode === 'idle' && (
          status.enabled ? (
            <>
              <p className="small"><span className="badge text-bg-success me-1">Enabled</span>{status.recoveryCodesRemaining} recovery codes remaining.</p>
              <button className="btn btn-outline-secondary btn-sm me-2" onClick={() => setMode('regen')}>New recovery codes</button>
              <button className="btn btn-outline-danger btn-sm" onClick={() => setMode('disable')}>Disable</button>
            </>
          ) : (
            <>
              <p className="small text-muted">Add an authenticator app (Google Authenticator, Authy, etc.). High-risk file access will then require your password and a code.</p>
              <button className="btn btn-primary btn-sm" onClick={() => setMode('password')}>Enable two-factor authentication</button>
            </>
          )
        )}

        {mode === 'password' && (
          <form onSubmit={doEnroll}>{pwInput}
            <button className="btn btn-primary btn-sm me-2" disabled={busy}>Continue</button>
            <button type="button" className="btn btn-link btn-sm" onClick={reset}>Cancel</button>
          </form>
        )}

        {mode === 'scan' && enroll && (
          <form onSubmit={doConfirm}>
            <p className="small">Scan this QR code with your authenticator app, then enter the 6-digit code it shows.</p>
            <img src={enroll.qrDataUrl} alt="QR code for your authenticator app" width="180" height="180" className="mb-2" />
            <p className="small text-muted">Can't scan? Enter this key manually: <code className="user-select-all">{enroll.secret}</code></p>
            {codeInput}
            <button className="btn btn-primary btn-sm me-2" disabled={busy}>Verify and enable</button>
            <button type="button" className="btn btn-link btn-sm" onClick={reset}>Cancel</button>
          </form>
        )}

        {mode === 'codes' && codes && (
          <div>
            <div className="alert alert-warning small">Save these recovery codes now. They are shown <strong>only once</strong>. Each works a single time if you lose your authenticator.</div>
            <pre className="bg-body-tertiary p-3 rounded user-select-all">{codes.join('\n')}</pre>
            <button className="btn btn-outline-secondary btn-sm mb-2" onClick={() => navigator.clipboard.writeText(codes.join('\n'))}>Copy</button>
            <div className="form-check mb-2">
              <input className="form-check-input" type="checkbox" id="mfaSaved" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
              <label className="form-check-label small" htmlFor="mfaSaved">I have saved these codes somewhere safe.</label>
            </div>
            <button className="btn btn-primary btn-sm" disabled={!saved} onClick={() => { setCodes(null); reset(); }}>Done</button>
          </div>
        )}

        {(mode === 'disable' || mode === 'regen') && (
          <form onSubmit={mode === 'disable' ? doDisable : doRegen}>
            <p className="small text-muted">{mode === 'disable' ? 'Confirm your password and a current code to disable two-factor authentication.' : 'Confirm your password and a current code. Your old recovery codes will stop working.'}</p>
            {pwInput}{codeInput}
            <button className={`btn btn-sm me-2 ${mode === 'disable' ? 'btn-danger' : 'btn-primary'}`} disabled={busy}>Confirm</button>
            <button type="button" className="btn btn-link btn-sm" onClick={reset}>Cancel</button>
          </form>
        )}
      </div>
    </div>
  );
}