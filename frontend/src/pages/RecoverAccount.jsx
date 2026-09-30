import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { generateSalt, deriveKek, DEFAULT_KDF_ITERATIONS } from '../crypto/kdf.js';
import { generateWrapIV, wrapMasterKey } from '../crypto/masterKey.js';
import { importRecoveryWrapKey, normalizeRecoveryKeyInput } from '../crypto/recoveryKey.js';
import { unwrapMasterKey } from '../crypto/masterKey.js';
import { bufferToBase64 } from '../crypto/encoding.js';
import * as authService from '../services/authService.js';
import { parseApiError } from '../utils/apiError.js';

export default function RecoverAccount() {
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: '', recoveryKey: '', newPassword: '' });
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const recoveryKey = normalizeRecoveryKeyInput(form.recoveryKey);

      // 1. Fetch the recovery ciphertext (public endpoint, rate-limited server-side).
      const bundle = await authService.getRecoveryBundle(form.email);

      // 2. Unwrap the Master Key LOCALLY using the recovery key. If the key is
      // wrong, this throws and nothing is sent to the server as a "success".
      const recoveryWrapKey = await importRecoveryWrapKey(recoveryKey);
      const masterKey = await unwrapMasterKey(bundle.recoveryWrappedMasterKey, recoveryWrapKey, bundle.recoveryIv);

      // 3. Re-wrap the SAME Master Key under a KEK derived from the new password.
      const salt = generateSalt();
      const kek = await deriveKek(form.newPassword, salt, DEFAULT_KDF_ITERATIONS);
      const masterKeyIv = generateWrapIV();
      const wrappedMasterKey = await wrapMasterKey(masterKey, kek, masterKeyIv);

      // 4. Server verifies the recovery key's hash and swaps the password + wrapping.
      await authService.recoverAccount({
        email: form.email,
        recoveryKey,
        newPassword: form.newPassword,
        kdfSalt: bufferToBase64(salt),
        kdfIterations: DEFAULT_KDF_ITERATIONS,
        wrappedMasterKey,
        masterKeyIv: bufferToBase64(masterKeyIv),
      });
      setDone(true);
    } catch (err) {
      setError(err.message || parseApiError(err).message);
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <div className="card shadow-sm">
        <div className="card-body p-4 text-center">
          <h2 className="h5 mb-3">Account recovered</h2>
          <p className="small text-muted">Your password has been reset and your files remain accessible.</p>
          <Link to="/login" className="btn btn-primary">Sign in</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="card shadow-sm">
      <div className="card-body p-4">
        <h2 className="h5 mb-3">Recover your account</h2>
        <div className="alert alert-info small">
          This only works if you saved the one-time recovery key shown at registration.
          Without it, your files cannot be recovered by anyone.
        </div>
        {error && <div className="alert alert-danger py-2 small">{error}</div>}
        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label className="form-label">Email</label>
            <input name="email" type="email" className="form-control" required value={form.email} onChange={handleChange} />
          </div>
          <div className="mb-3">
            <label className="form-label">Recovery key</label>
            <input name="recoveryKey" className="form-control font-monospace" required
              placeholder="XXXX-XXXX-XXXX-XXXX" value={form.recoveryKey} onChange={handleChange} />
          </div>
          <div className="mb-3">
            <label className="form-label">New password</label>
            <input name="newPassword" type="password" className="form-control" minLength={12} required
              autoComplete="new-password" value={form.newPassword} onChange={handleChange} />
          </div>
          <button className="btn btn-primary w-100" disabled={busy}>{busy ? 'Recovering...' : 'Recover account'}</button>
        </form>
        <div className="text-center mt-3 small"><Link to="/login">Back to sign in</Link></div>
      </div>
    </div>
  );
}