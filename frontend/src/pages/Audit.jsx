import PageHeader from '../components/PageHeader.jsx';
import { mockAuditLogs } from '../utils/mockData.js';
import { formatDate } from '../utils/format.js';

const resultClass = { SUCCESS: 'success', FAILURE: 'danger', DENIED: 'warning' };

export default function Audit() {
  return (
    <>
      <PageHeader title="Audit log" subtitle="Sample data. Real logging is implemented in Phase 13." />
      <div className="card shadow-sm">
        <div className="table-responsive">
          <table className="table table-sm align-middle mb-0">
            <thead className="table-light">
              <tr><th>Time</th><th>Event</th><th>File</th><th>Result</th><th>IP</th></tr>
            </thead>
            <tbody>
              {mockAuditLogs.map((l) => (
                <tr key={l.id}>
                  <td className="small">{formatDate(l.at)}</td>
                  <td>{l.eventType}</td>
                  <td>{l.fileName || '-'}</td>
                  <td><span className={`badge text-bg-${resultClass[l.result]}`}>{l.result}</span></td>
                  <td className="small">{l.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}