import { useEffect, useState } from 'react';
import PageHeader from '../components/PageHeader.jsx';
import StatCard from '../components/StatCard.jsx';
import { useAuth } from '../hooks/useAuth.js';
import * as fileService from '../services/fileService.js';
import * as auditService from '../services/auditService.js';
import { formatDate } from '../utils/format.js';

const DENIED_EVENT_TYPES = ['ACCESS_DENIED', 'LOGIN_FAILED', 'STEP_UP_VERIFICATION'];

export default function Security() {
  const { user } = useAuth();
  const isAdmin = user.role === 'ADMIN';
  const [files, setFiles] = useState([]);
  const [stats, setStats] = useState({ byEventType: [], byResult: [] });
  const [recent, setRecent] = useState([]);

  useEffect(() => {
    fileService.listFiles().then(setFiles).catch(() => {});
    const statsFn = isAdmin ? auditService.getAllStats : auditService.getMyStats;
    statsFn().then(setStats).catch(() => {});
    const logsFn = isAdmin ? auditService.getAllLogs : auditService.getMyLogs;
    logsFn({ pageSize: 10 }).then((d) => setRecent(d.logs.filter((l) => l.result !== 'SUCCESS'))).catch(() => {});
  }, [isAdmin]);

  const count = (level) => files.filter((f) => f.riskLevel === level).length;
  const blockedCount = stats.byResult.find((r) => r.result === 'DENIED')?.count || 0;
  const failureCount = stats.byResult.find((r) => r.result === 'FAILURE')?.count || 0;

  return (
    <>
      <PageHeader title="Security" subtitle={isAdmin ? 'System-wide security posture' : 'Your security posture'} />
      <div className="row g-3 mb-4">
        <div className="col-6 col-lg-3"><StatCard label="Encrypted files" value={files.length} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Low risk" value={count('LOW')} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Medium risk" value={count('MEDIUM')} /></div>
        <div className="col-6 col-lg-3"><StatCard label="High risk" value={count('HIGH')} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Critical risk" value={count('CRITICAL')} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Blocked attempts" value={blockedCount} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Failed attempts" value={failureCount} /></div>
      </div>

      <div className="row g-3">
        <div className="col-lg-6">
          <div className="card shadow-sm h-100">
            <div className="card-header fw-semibold">Encryption status</div>
            <ul className="list-group list-group-flush">
              <li className="list-group-item d-flex justify-content-between"><span>Cipher</span><span>AES-256-GCM</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Encryption location</span><span>Browser (client-side)</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Risk classification</span><span>Server-side, rule-based, transparent</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Step-up verification</span><span>HIGH/CRITICAL files only</span></li>
            </ul>
          </div>
        </div>
        <div className="col-lg-6">
          <div className="card shadow-sm h-100">
            <div className="card-header fw-semibold">Recent security events</div>
            <ul className="list-group list-group-flush" style={{ maxHeight: 280, overflowY: 'auto' }}>
              {recent.length === 0 && <li className="list-group-item text-muted small">No denied or failed events recorded.</li>}
              {recent.map((l) => (
                <li key={l.id} className="list-group-item d-flex justify-content-between">
                  <span>{l.eventType} {isAdmin && l.userId && <small className="text-muted">(user {l.userId})</small>}</span>
                  <small className="text-muted">{formatDate(l.createdAt)}</small>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </>
  );
}