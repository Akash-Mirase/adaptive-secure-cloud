import { Link, useNavigate } from 'react-router-dom';

export default function Login() {
  const navigate = useNavigate();

  const handleSubmit = (e) => {
    e.preventDefault();
    // UI ONLY: real authentication is implemented in Phase 5.
    navigate('/dashboard');
  };

  return (
    <div className="card shadow-sm">
      <div className="card-body p-4">
        <h2 className="h5 mb-3">Sign in</h2>
        <div className="alert alert-warning py-2 small">Phase 2: UI only. No authentication yet.</div>
        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label className="form-label" htmlFor="email">Email</label>
            <input id="email" type="email" className="form-control" required autoComplete="username" />
          </div>
          <div className="mb-3">
            <label className="form-label" htmlFor="password">Password</label>
            <input id="password" type="password" className="form-control" required autoComplete="current-password" />
          </div>
          <button className="btn btn-primary w-100">Sign in</button>
        </form>
        <div className="text-center mt-3 small">
          No account? <Link to="/register">Register</Link>
        </div>
      </div>
    </div>
  );
}