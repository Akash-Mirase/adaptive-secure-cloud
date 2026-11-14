import { useEffect, useState } from 'react';
import * as alertService from '../services/alertService.js';
import { parseApiError } from '../utils/apiError.js';
import { formatDate } from '../utils/format.js';

const SEVERITY = { LOW: 'secondary', MEDIUM: 'warning', HIGH: 'danger' };
const PAGE_SIZE = 5;

export default function AlertsPanel({ isAdmin }) {
  const [page, setPage] = useState(1);
  const [data, setData] = useState({ alerts: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    const fn = isAdmin ? alertService.getAllAlerts : alertService.getMyAlerts;
    fn({ page, pageSize: PAGE_SIZE })
      .then((d) => { if (!cancelled) setData(d); })
      .catch((e) => { if (!cancelled) setError(parseApiError(e).message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [isAdmin, page]);

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));

  return (
    <div className="card shadow-sm mt-3">
      <div className="card-header fw-semibold">Security alerts {isAdmin ? '(all users)' : ''}</div>
      {error && <div className="alert alert-danger m-3 py-2 small" role="alert">{error}</div>}
      <ul className="list-group list-group-flush" aria-live="polite">
        {loading && <li className="list-group-item text-muted small">Loading...</li>}
        {!loading && !error && data.alerts.length === 0 && (
          <li className="list-group-item text-muted small">No alerts. Nothing unusual detected.</li>
        )}
        {data.alerts.map((a) => (
          <li key={a.id} className="list-group-item">
            <div className="d-flex justify-content-between align-items-start">
              <div>
                <span className={`badge text-bg-${SEVERITY[a.severity]} me-2`}>{a.severity}</span>
                {a.message}
                {isAdmin && <small className="text-muted"> (user {a.userId})</small>}
                {a.restriction !== 'NONE' && (
                  <div className="small text-muted">
                    Temporary response: {a.restriction.replaceAll('_', ' ').toLowerCase()}
                    {a.expiresAt && <> until {formatDate(a.expiresAt)}</>}
                  </div>
                )}
              </div>
              <small className="text-muted ms-2 text-nowrap">{formatDate(a.createdAt)}</small>
            </div>
          </li>
        ))}
      </ul>
      {totalPages > 1 && (
        <div className="card-footer d-flex justify-content-between align-items-center">
          <small className="text-muted">Page {page} of {totalPages}</small>
          <div className="btn-group">
            <button className="btn btn-outline-secondary btn-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
            <button className="btn btn-outline-secondary btn-sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      )}
    </div>
  );
}