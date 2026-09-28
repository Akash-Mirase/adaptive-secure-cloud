import PageHeader from '../components/PageHeader.jsx';

export default function Profile() {
  return (
    <>
      <PageHeader title="Profile" subtitle="Account and encryption key settings" />
      <div className="row g-3">
        <div className="col-lg-6">
          <div className="card shadow-sm">
            <div className="card-header fw-semibold">Account</div>
            <div className="card-body">
              <div className="mb-3"><label className="form-label">Name</label><input className="form-control" disabled placeholder="Loaded in Phase 5" /></div>
              <div className="mb-0"><label className="form-label">Email</label><input className="form-control" disabled placeholder="Loaded in Phase 5" /></div>
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