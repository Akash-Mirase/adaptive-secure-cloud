import { useState } from 'react';
import PageHeader from '../components/PageHeader.jsx';
import { useAuth } from '../hooks/useAuth.js';
import { formatDate } from '../utils/format.js';
import * as authService from '../services/authService.js';
import { deriveKek } from '../crypto/kdf.js';
import { unwrapMasterKey, generateWrapIV, wrapMasterKey } from '../crypto/masterKey.js';
import { generateRecoveryKey, importRecoveryWrapKey } from '../crypto/recoveryKey.js';
import { base64ToBuffer, bufferToBase64 } from '../crypto/encoding.js';
import { parseApiError } from '../utils/apiError.js';

export default function Profile() {
  const { user } = useAuth();

  const [step, setStep] = useState('idle'); // idle | confirm | show | done
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [newRecoveryKey, setNewRecoveryKey] = useState(null);
  const [confirmed, setConfirmed] = useState(false);

  const openConfirm = () => { setStep('confirm'); setError(''); setPassword(''); };
  const cancel = () => { setStep('idle'); setPassword(''); setError(''); setConfirmed(false); };

  const handleGenerate = async (e) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      // Re-derive the KEK from the password the user just typed and unwrap the
      // Master Key fresh — this independently proves the password is correct
      // right now, rather than trusting the already-unlocked session key.
      const { keys } = await authService.getKeyBundle();
      const kek = await deriveKek(password, new Uint8Array(base64ToBuffer(keys.kdfSalt)), keys.kdfIterations);
      const masterKey = await unwrapMasterKey(keys.wrappedMasterKey, kek, keys.masterKeyIv); // throws on wrong password

      const recoveryKey = generateRecoveryKey();
      const recoveryWrapKey = await importRecoveryWrapKey(recoveryKey);
      const recoveryIv = generateWrapIV();
      const recoveryWrappedMasterKey = await wrapMasterKey(masterKey, recoveryWrapKey, recoveryIv);

      await authService.regenerateRecoveryKey({
        recoveryWrappedMasterKey,
        recoveryIv: bufferToBase64(recoveryIv),
        recoveryKey,
      });

      setNewRecoveryKey(recoveryKey);
      setStep('show');
    } catch (err) {
      setError(err.message || parseApiError(err).message);
    } finally {
      setBusy(false);
    }
  };

  const finish = () => {
    setStep('done');
    setNewRecoveryKey(null);
    setPassword('');
    setConfirmed(false);
  };

  return (
    <>
      <PageHeader title="Profile" subtitle="Account and encryption key settings" />
      <div className="row g-3">
        <div className="col-lg-6">
          <div className="card shadow-sm">
            <div className="card-header fw-semibold">Account</div>
            <div className="card-body">
              <div className="mb-3"><label className="form-label">Name</label><input className="form-control" value={user.name} disabled readOnly /></div>
              <div className="mb-3"><label className="form-label">Email</label><input className="form-control" value={user.email} disabled readOnly /></div>
              <div className="mb-3"><label className="form-label">Role</label><input className="form-control" value={user.role} disabled readOnly /></div>
              <div className="text-muted small">Member since {formatDate(user.createdAt)}</div>
            </div>
          </div>
        </div>

        <div className="col-lg-6">
          <div className="card shadow-sm">
            <div className="card-header fw-semibold">Encryption keys</div>
            <div className="card-body">
              <p className="small text-muted">
                Your files are protected by keys derived from your password. If you lose your password and
                have no recovery key, your encrypted files cannot be recovered. This is inherent to
                client-side encryption.
              </p>

              {step === 'idle' && (
                <button className="btn btn-outline-secondary" onClick={openConfirm}>Generate new recovery key</button>
              )}

              {step === 'confirm' && (
                <form onSubmit={handleGenerate}>
                  <div className="alert alert-warning small">
                    Generating a new recovery key immediately invalidates your old one. Confirm your password to continue.
                  </div>
                  {error && <div className="alert alert-danger py-2 small">{error}</div>}
                  <input
                    type="password" className="form-control mb-2" placeholder="Password" autoFocus
                    autoComplete="current-password" value={password}
                    onChange={(e) => setPassword(e.target.value)} required
                  />
                  <div className="d-flex gap-2">
                    <button className="btn btn-primary" disabled={busy}>{busy ? 'Verifying...' : 'Continue'}</button>
                    <button type="button" className="btn btn-link" onClick={cancel}>Cancel</button>
                  </div>
                </form>
              )}

              {step === 'show' && newRecoveryKey && (
                <div>
                  <div className="alert alert-warning small">
                    This is the <strong>only time</strong> this new key will be shown. Your old recovery key no longer works.
                  </div>
                  <div className="p-3 bg-body-tertiary rounded text-center font-monospace fs-6 mb-3 user-select-all">
                    {newRecoveryKey}
                  </div>
                  <button className="btn btn-outline-secondary w-100 mb-3" onClick={() => navigator.clipboard.writeText(newRecoveryKey)}>
                    Copy to clipboard
                  </button>
                  <div className="form-check mb-3">
                    <input className="form-check-input" type="checkbox" id="confirmNewSaved"
                      checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                    <label className="form-check-label small" htmlFor="confirmNewSaved">
                      I have saved this recovery key somewhere safe.
                    </label>
                  </div>
                  <button className="btn btn-primary w-100" disabled={!confirmed} onClick={finish}>Done</button>
                </div>
              )}

              {step === 'done' && (
                <div className="alert alert-success small mb-0">
                  Recovery key updated.
                  <button className="btn btn-sm btn-link p-0 ms-1" onClick={() => setStep('idle')}>Generate another</button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}