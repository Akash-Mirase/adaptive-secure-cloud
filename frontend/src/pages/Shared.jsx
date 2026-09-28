import PageHeader from '../components/PageHeader.jsx';
import RiskBadge from '../components/RiskBadge.jsx';
import { mockSharedFiles } from '../utils/mockData.js';
import { formatDate } from '../utils/format.js';

export default function Shared() {
  return (
    <>
      <PageHeader title="Shared with me" subtitle="Sample data. Sharing is implemented in Phase 12." />
      <div className="card shadow-sm">
        <div className="table-responsive">
          <table className="table align-middle mb-0">
            <thead className="table-light">
              <tr><th>Name</th><th>Owner</th><th>Permission</th><th>Risk</th><th>Shared</th></tr>
            </thead>
            <tbody>
              {mockSharedFiles.map((f) => (
                <tr key={f.id}>
                  <td>{f.name}</td>
                  <td>{f.owner}</td>
                  <td><span className="badge text-bg-info">{f.permission}</span></td>
                  <td><RiskBadge level={f.riskLevel} /></td>
                  <td className="small">{formatDate(f.sharedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}