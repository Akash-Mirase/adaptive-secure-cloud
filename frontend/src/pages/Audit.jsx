import { useEffect, useState } from 'react';
import PageHeader from '../components/PageHeader.jsx';
import { useAuth } from '../hooks/useAuth.js';
import * as auditService from '../services/auditService.js';
import { parseApiError } from '../utils/apiError.js';
import { formatDate } from '../utils/format.js';

const EVENT_TYPES = [
  'REGISTER', 'LOGIN', 'LOGIN_FAILED', 'LOGOUT', 'UPLOAD', 'DOWNLOAD', 'DELETE',
  'SHARE', 'UNSHARE', 'ACCESS_DENIED', 'KEY_OPERATION', 'RISK_CLASSIFICATION',
  'SECURITY_POLICY_APPLIED', 'STEP_UP_VERIFICATION', 'INTEGRITY_FAILURE',
];
const RESULT_BADGE = { SUCCESS: 'success', FAILURE: 'danger', DENIED: 'warning' };

export default function Audit() {
  const { user } = useAuth();
  const isAdmin = user.role === 'ADMIN';

  const [filters, setFilters] = useState({ eventType: '', result: '', dateFrom: '', dateTo: '' });
  const [page, setPage] = useState(1);
  const [data, setData] = useState({ logs: [], total: 0, pageSize: 25 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const params = { ...filters, page };
      Object.keys(params).forEach((k) => { if (!params[k]) delete params[k]; });
      const fetchFn = isAdmin ? auditService.getAllLogs : auditService.getMyLogs;
      setData(await fetchFn(params));
    } catch (err) {
      setError(parseApiError(err).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [filters, page]); // eslint-disable-line react-hooks/exhaustive-deps

  const totalPages = Math.max(1, Math.ceil(data.total / (data.pageSize || 25)));
  const updateFilter = (key, value) => { setPage(1); setFilters((f) => ({ ...f, [key]: value })); };

  return (
    <>
      <PageHeader
        title={isAdmin ? 'Audit log (all users)' : 'Audit log'}
        subtitle={isAdmin ? 'Security events across every account' : 'Your own account activity'}
      />

      {error && <div className="alert alert-danger">{error}</div>}

      <div className="row g-2 mb-3">
        <div className="col-6 col-md-3">
          <select className="form-select" value={filters.eventType} onChange={(e) => updateFilter('eventType', e.target.value)}>
            <option value="">All event types</option>
            {EVENT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div className="col-6 col-md-2">
          <select className="form-select" value={filters.result} onChange={(e) => updateFilter('result', e.target.value)}>
            <option value="">All results</option>
            <option value="SUCCESS">SUCCESS</option>
            <option value="FAILURE">FAILURE</option>
            <option value="DENIED">DENIED</option>
          </select>
        </div>
        <div className="col-6 col-md-3">
          <input type="date" className="form-control" value={filters.dateFrom} onChange={(e) => updateFilter('dateFrom', e.target.value)} />
        </div>
        <div className="col-6 col-md-3">
          <input type="date" className="form-control" value={filters.dateTo} onChange={(e) => updateFilter('dateTo', e.target.value)} />
        </div>
      </div>

      <div className="card shadow-sm">
        <div className="table-responsive">
          <table className="table table-sm align-middle mb-0">
            <thead className="table-light">
              <tr>
                <th>Time</th>
                {isAdmin && <th>User</th>}
                <th>Event</th><th>File</th><th>Result</th><th>IP</th>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={isAdmin ? 6 : 5} className="text-center py-4 text-muted">Loading...</td></tr>}
              {!loading && data.logs.length === 0 && (
                <tr><td colSpan={isAdmin ? 6 : 5} className="text-center py-4 text-muted">No matching events.</td></tr>
              )}
              {data.logs.map((l) => (
                <tr key={l.id}>
                  <td className="small">{formatDate(l.createdAt)}</td>
                  {isAdmin && <td className="small">{l.userId ?? '—'}</td>}
                  <td>{l.eventType}</td>
                  <td className="small font-monospace">{l.fileId ? l.fileId.slice(0, 8) : '-'}</td>
                  <td><span className={`badge text-bg-${RESULT_BADGE[l.result]}`}>{l.result}</span></td>
                  <td className="small">{l.ipAddress || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {totalPages > 1 && (
        <div className="d-flex justify-content-between align-items-center mt-3">
          <span className="small text-muted">Page {page} of {totalPages} · {data.total} events</span>
          <div className="btn-group">
            <button className="btn btn-outline-secondary btn-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
            <button className="btn btn-outline-secondary btn-sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      )}
    </>
  );
}