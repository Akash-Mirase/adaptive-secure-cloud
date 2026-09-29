import PageHeader from '../components/PageHeader.jsx';
import { useAuth } from '../hooks/useAuth.js';
import { formatDate } from '../utils/format.js';

export default function Profile() {
  const { user } = useAuth();
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
              <button className="btn btn-outline-secondary" disabled>Generate recovery key (Phase 8)</button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}