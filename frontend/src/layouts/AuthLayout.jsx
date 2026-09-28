import { Outlet } from 'react-router-dom';

export default function AuthLayout() {
  return (
    <div className="min-vh-100 d-flex align-items-center bg-light">
      <div className="container" style={{ maxWidth: 440 }}>
        <div className="text-center mb-4">
          <h1 className="h4 mb-0">Adaptive Secure Cloud</h1>
          <small className="text-muted">Client-side encrypted storage</small>
        </div>
        <Outlet />
      </div>
    </div>
  );
}