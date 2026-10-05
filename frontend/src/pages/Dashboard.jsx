import { useEffect, useState } from 'react';
import PageHeader from '../components/PageHeader.jsx';
import StatCard from '../components/StatCard.jsx';
import * as fileService from '../services/fileService.js';
import * as auditService from '../services/auditService.js';
import { useAuth } from '../hooks/useAuth.js';
import { formatBytes, formatDate } from '../utils/format.js';

const LEVELS = [
  ['LOW', 'bg-success'],
  ['MEDIUM', 'bg-warning'],
  ['HIGH', 'bg-orange'],
  ['CRITICAL', 'bg-danger'],
];

export default function Dashboard() {
  const { user } = useAuth();
  const isAdmin = user.role === 'ADMIN';

  const [files, setFiles] = useState([]);
  const [recentLogs, setRecentLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');

    const logsFn = isAdmin ? auditService.getAllLogs : auditService.getMyLogs;

    Promise.all([fileService.listFiles(), logsFn({ pageSize: 5 })])
      .then(([filesData, logsData]) => {
        if (cancelled) return;
        setFiles(filesData);
        setRecentLogs(logsData.logs);
      })
      .catch((err) => {
        if (!cancelled) setError(err.response?.data?.message || 'Could not load dashboard data.');
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [isAdmin]);

  const total = files.length;
  const storage = files.reduce((sum, f) => sum + f.fileSize, 0);
  const count = (level) => files.filter((f) => f.riskLevel === level).length;

  if (loading) {
    return (
      <div className="d-flex justify-content-center py-5">
        <div className="spinner-border" role="status" aria-label="Loading" />
      </div>
    );
  }

  return (
    <>
      <PageHeader title="Dashboard" subtitle="Overview of your files and recent activity" />

      {error && <div className="alert alert-danger">{error}</div>}

      <div className="row g-3 mb-4">
        <div className="col-6 col-lg-3"><StatCard label="Total files" value={total} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Encrypted files" value={total} hint="all files are encrypted" /></div>
        <div className="col-6 col-lg-3"><StatCard label="Storage used" value={formatBytes(storage)} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Critical files" value={count('CRITICAL')} /></div>
      </div>

      <div className="row g-3">
        <div className="col-lg-6">
          <div className="card shadow-sm h-100">
            <div className="card-header fw-semibold">Risk distribution</div>
            <div className="card-body">
              {total === 0 && <p className="text-muted small mb-0">No files uploaded yet.</p>}
              {LEVELS.map(([level, color]) => (
                <div className="mb-3" key={level}>
                  <div className="d-flex justify-content-between small">
                    <span>{level}</span><span>{count(level)}</span>
                  </div>
                  <div className="progress" style={{ height: 10 }}>
                    <div
                      className={`progress-bar ${color}`}
                      style={{ width: `${total ? (count(level) / total) * 100 : 0}%`, ...(level === 'HIGH' ? { backgroundColor: '#fd7e14' } : {}) }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="col-lg-6">
          <div className="card shadow-sm h-100">
            <div className="card-header fw-semibold">Recent activity</div>
            <ul className="list-group list-group-flush">
              {recentLogs.length === 0 && <li className="list-group-item text-muted small">No activity yet.</li>}
              {recentLogs.map((log) => (
                <li className="list-group-item d-flex justify-content-between" key={log.id}>
                  <span>{log.eventType}</span>
                  <small className="text-muted">{formatDate(log.createdAt)}</small>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </>
  );
}