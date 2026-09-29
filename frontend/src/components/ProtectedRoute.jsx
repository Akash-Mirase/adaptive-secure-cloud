import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth.js';

// NOTE: this only improves the user experience. Anyone can bypass browser code.
// The REAL protection is the backend `authenticate` middleware on every API route.
export default function ProtectedRoute() {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="d-flex justify-content-center py-5">
        <div className="spinner-border" role="status" aria-label="Loading" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;
  return <Outlet />;
}