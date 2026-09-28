import { Link } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import RiskBadge from '../components/RiskBadge.jsx';
import { mockFiles } from '../utils/mockData.js';
import { formatBytes, formatDate } from '../utils/format.js';

export default function Files() {
  return (
    <>
      <PageHeader title="My Files" subtitle="Sample data. Actions are enabled in later phases.">
        <Link to="/upload" className="btn btn-primary">Upload file</Link>
      </PageHeader>

      <div className="card shadow-sm">
        <div className="table-responsive">
          <table className="table table-hover align-middle mb-0">
            <thead className="table-light">
              <tr>
                <th>Name</th><th>Size</th><th>Type</th><th>Risk</th><th>Status</th><th>Created</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {mockFiles.map((f) => (
                <tr key={f.id}>
                  <td>{f.name}</td>
                  <td>{formatBytes(f.size)}</td>
                  <td className="small text-muted">{f.type}</td>
                  <td><RiskBadge level={f.riskLevel} /> <small className="text-muted">({f.riskScore})</small></td>
                  <td><span className="badge text-bg-secondary">Encrypted (sample)</span></td>
                  <td className="small">{formatDate(f.createdAt)}</td>
                  <td className="text-nowrap">
                    <button className="btn btn-sm btn-outline-primary me-1" disabled>Download</button>
                    <button className="btn btn-sm btn-outline-secondary me-1" disabled>Share</button>
                    <button className="btn btn-sm btn-outline-danger me-1" disabled>Delete</button>
                    <button className="btn btn-sm btn-outline-dark" disabled>Details</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}