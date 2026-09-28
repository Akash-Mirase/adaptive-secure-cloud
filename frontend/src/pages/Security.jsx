import PageHeader from '../components/PageHeader.jsx';
import StatCard from '../components/StatCard.jsx';
import { mockFiles, mockAuditLogs } from '../utils/mockData.js';
import { formatDate } from '../utils/format.js';

export default function Security() {
  const count = (level) => mockFiles.filter((f) => f.riskLevel === level).length;
  const blocked = mockAuditLogs.filter((l) => l.eventType === 'ACCESS_DENIED').length;

  return (
    <>
      <PageHeader title="Security" subtitle="Sample data. Live metrics arrive with Phases 10 to 13." />

      <div className="row g-3 mb-4">
        <div className="col-6 col-lg-3"><StatCard label="Encrypted files" value={mockFiles.length} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Low risk" value={count('LOW')} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Medium risk" value={count('MEDIUM')} /></div>
        <div className="col-6 col-lg-3"><StatCard label="High risk" value={count('HIGH')} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Critical risk" value={count('CRITICAL')} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Blocked attempts" value={blocked} /></div>
      </div>

      <div className="row g-3">
        <div className="col-lg-6">
          <div className="card shadow-sm h-100">
            <div className="card-header fw-semibold">Encryption status</div>
            <ul className="list-group list-group-flush">
              <li className="list-group-item d-flex justify-content-between"><span>Cipher</span><span>AES-256-GCM</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Encryption location</span><span>Browser (client-side)</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Key per file</span><span>Yes</span></li>
            </ul>
          </div>
        </div>
        <div className="col-lg-6">
          <div className="card shadow-sm h-100">
            <div className="card-header fw-semibold">Recent security events</div>
            <ul className="list-group list-group-flush">
              {mockAuditLogs.filter((l) => l.result !== 'SUCCESS').map((l) => (
                <li className="list-group-item d-flex justify-content-between" key={l.id}>
                  <span>{l.eventType} <small className="text-muted">from {l.ip}</small></span>
                  <small className="text-muted">{formatDate(l.at)}</small>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </>
  );
}