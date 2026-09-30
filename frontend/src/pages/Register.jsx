import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth.js';
import { parseApiError } from '../utils/apiError.js';
import { generateSalt, deriveKek, DEFAULT_KDF_ITERATIONS } from '../crypto/kdf.js';
import { generateMasterKey, generateWrapIV, wrapMasterKey } from '../crypto/masterKey.js';
import { generateRecoveryKey, importRecoveryWrapKey } from '../crypto/recoveryKey.js';
import { bufferToBase64 } from '../crypto/encoding.js';


export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [recoveryKey, setRecoveryKey] = useState(null); // shown once, then discarded from memory
  const [savedConfirmed, setSavedConfirmed] = useState(false);

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });
  const invalid = (field) => (fieldErrors[field] ? 'is-invalid' : '');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setFieldErrors({});
    setSubmitting(true);
    try {
      // 1. Build the ENTIRE key hierarchy client-side before anything is sent.
      const salt = generateSalt();
      const kek = await deriveKek(form.password, salt, DEFAULT_KDF_ITERATIONS);
      const masterKey = await generateMasterKey();

      const masterKeyIv = generateWrapIV();
      const wrappedMasterKey = await wrapMasterKey(masterKey, kek, masterKeyIv);

      const plainRecoveryKey = generateRecoveryKey();
      const recoveryWrapKey = await importRecoveryWrapKey(plainRecoveryKey);
      const recoveryIv = generateWrapIV();
      const recoveryWrappedMasterKey = await wrapMasterKey(masterKey, recoveryWrapKey, recoveryIv);

      // 2. Send the user's data plus ONLY non-secret/ciphertext material,
      // plus the recovery key ONCE (purely so the server can hash it — see auth.service.js).
      await register({
        name: form.name,
        email: form.email,
        password: form.password,
        kdfSalt: bufferToBase64(salt),
        kdfIterations: DEFAULT_KDF_ITERATIONS,
        wrappedMasterKey,
        masterKeyIv: bufferToBase64(masterKeyIv),
        recoveryWrappedMasterKey,
        recoveryIv: bufferToBase64(recoveryIv),
        recoveryKey: plainRecoveryKey,
      });

      setRecoveryKey(plainRecoveryKey); // now shown to the user, once
    } catch (err) {
      const parsed = parseApiError(err);
      setError(parsed.message);
      setFieldErrors(parsed.fieldErrors);
    } finally {
      setSubmitting(false);
    }
  };

  if (recoveryKey) {
    return (
      <div className="card shadow-sm">
        <div className="card-body p-4">
          <h2 className="h5 mb-3">Save your recovery key</h2>
          <div className="alert alert-warning small">
            This is the <strong>only time</strong> this key will ever be shown. If you forget your password and
            lose this key, your encrypted files cannot be recovered by anyone, including us.
          </div>
          <div className="p-3 bg-body-tertiary rounded text-center font-monospace fs-5 mb-3 user-select-all">
            {recoveryKey}
          </div>
          <button
            className="btn btn-outline-secondary w-100 mb-3"
            onClick={() => navigator.clipboard.writeText(recoveryKey)}
          >
            Copy to clipboard
          </button>
          <div className="form-check mb-3">
            <input className="form-check-input" type="checkbox" id="confirmSaved"
              checked={savedConfirmed} onChange={(e) => setSavedConfirmed(e.target.checked)} />
            <label className="form-check-label small" htmlFor="confirmSaved">
              I have saved this recovery key somewhere safe.
            </label>
          </div>
          <button className="btn btn-primary w-100" disabled={!savedConfirmed}
            onClick={() => navigate('/login', { replace: true, state: { registered: true } })}>
            Continue to sign in
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="card shadow-sm">
      <div className="card-body p-4">
        <h2 className="h5 mb-3">Create account</h2>
        {error && <div className="alert alert-danger py-2 small">{error}</div>}
        <form onSubmit={handleSubmit} noValidate>
          <div className="mb-3">
            <label className="form-label" htmlFor="name">Name</label>
            <input id="name" name="name" className={`form-control ${invalid('name')}`} value={form.name} onChange={handleChange} />
            <div className="invalid-feedback">{fieldErrors.name}</div>
          </div>
          <div className="mb-3">
            <label className="form-label" htmlFor="email">Email</label>
            <input id="email" name="email" type="email" className={`form-control ${invalid('email')}`}
              autoComplete="username" value={form.email} onChange={handleChange} />
            <div className="invalid-feedback">{fieldErrors.email}</div>
          </div>
          <div className="mb-3">
            <label className="form-label" htmlFor="password">Password</label>
            <input id="password" name="password" type="password" className={`form-control ${invalid('password')}`}
              autoComplete="new-password" value={form.password} onChange={handleChange} />
            <div className="invalid-feedback">{fieldErrors.password}</div>
            <div className="form-text">
              Minimum 12 characters. This password derives the key that protects all your files.
              You will get a one-time recovery key after registering — save it somewhere safe.
            </div>
          </div>
          <button className="btn btn-primary w-100" disabled={submitting}>
            {submitting ? 'Creating account...' : 'Register'}
          </button>
        </form>
        <div className="text-center mt-3 small">
          Already registered? <Link to="/login">Sign in</Link>
        </div>
      </div>
    </div>
  );
}