import { Link, useNavigate } from 'react-router-dom';

export default function Register() {
  const navigate = useNavigate();

  const handleSubmit = (e) => {
    e.preventDefault();
    // UI ONLY: real registration is implemented in Phase 5.
    navigate('/login');
  };

  return (
    <div className="card shadow-sm">
      <div className="card-body p-4">
        <h2 className="h5 mb-3">Create account</h2>
        <div className="alert alert-warning py-2 small">Phase 2: UI only. Nothing is saved.</div>
        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label className="form-label" htmlFor="name">Name</label>
            <input id="name" className="form-control" required />
          </div>
          <div className="mb-3">
            <label className="form-label" htmlFor="email">Email</label>
            <input id="email" type="email" className="form-control" required autoComplete="username" />
          </div>
          <div className="mb-3">
            <label className="form-label" htmlFor="password">Password</label>
            <input id="password" type="password" className="form-control" minLength={12} required autoComplete="new-password" />
            <div className="form-text">
              Minimum 12 characters. This password will also protect your encryption keys (Phase 8),
              so choose a strong one. If you forget it, files may be unrecoverable without a recovery key.
            </div>
          </div>
          <button className="btn btn-primary w-100">Register</button>
        </form>
        <div className="text-center mt-3 small">
          Already registered? <Link to="/login">Sign in</Link>
        </div>
      </div>
    </div>
  );
}