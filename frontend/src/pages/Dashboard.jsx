import PageHeader from '../components/PageHeader.jsx';
import StatCard from '../components/StatCard.jsx';
import { mockFiles, mockAuditLogs } from '../utils/mockData.js';
import { formatBytes, formatDate } from '../utils/format.js';

const LEVELS = [
  ['LOW', 'bg-success'],
  ['MEDIUM', 'bg-warning'],
  ['HIGH', 'bg-orange'],
  ['CRITICAL', 'bg-danger'],
];

export default function Dashboard() {
  const total = mockFiles.length;
  const storage = mockFiles.reduce((sum, f) => sum + f.size, 0);
  const count = (level) => mockFiles.filter((f) => f.riskLevel === level).length;

  return (
    <>
      <PageHeader title="Dashboard" subtitle="Overview (sample data)" />

      <div className="row g-3 mb-4">
        <div className="col-6 col-lg-3"><StatCard label="Total files" value={total} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Encrypted files" value={total} hint="all files" /></div>
        <div className="col-6 col-lg-3"><StatCard label="Storage used" value={formatBytes(storage)} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Critical files" value={count('CRITICAL')} /></div>
      </div>

      <div className="row g-3">
        <div className="col-lg-6">
          <div className="card shadow-sm h-100">
            <div className="card-header fw-semibold">Risk distribution</div>
            <div className="card-body">
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
              {mockAuditLogs.slice(0, 5).map((log) => (
                <li className="list-group-item d-flex justify-content-between" key={log.id}>
                  <span>{log.eventType}{log.fileName && <small className="text-muted"> · {log.fileName}</small>}</span>
                  <small className="text-muted">{formatDate(log.at)}</small>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </>
  );
}