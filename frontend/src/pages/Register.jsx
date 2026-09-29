import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth.js';
import { parseApiError } from '../utils/apiError.js';

export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });
  const invalid = (field) => (fieldErrors[field] ? 'is-invalid' : '');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setFieldErrors({});
    setSubmitting(true);
    try {
      await register(form);
      navigate('/login', { replace: true, state: { registered: true } });
    } catch (err) {
      const parsed = parseApiError(err);
      setError(parsed.message);
      setFieldErrors(parsed.fieldErrors);
    } finally {
      setSubmitting(false);
    }
  };

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
              Minimum 12 characters. This password will also protect your encryption keys (Phase 8),
              so choose a strong one. If you forget it, files may be unrecoverable without a recovery key.
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