import { useEffect, useState } from 'react';
import PageHeader from '../components/PageHeader.jsx';
import RiskBadge from '../components/RiskBadge.jsx';
import StepUpModal from '../components/StepUpModal.jsx';
import * as fileService from '../services/fileService.js';
import { parseApiError, isStepUpRequired } from '../utils/apiError.js';
import { formatBytes, formatDate } from '../utils/format.js';

export default function Shared() {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busyId, setBusyId] = useState(null);
  const [stepUpFile, setStepUpFile] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      setFiles(await fileService.listSharedWithMe());
    } catch (err) {
      setError(parseApiError(err).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); }, []);

  const handleDownload = async (file) => {
    setBusyId(file.id);
    setError('');
    try {
      await fileService.downloadFile(file.id, file.originalName, file.mimeType);
    } catch (err) {
      if (isStepUpRequired(err)) setStepUpFile(file);
      else setError(parseApiError(err).message);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <>
      <PageHeader title="Shared with me" subtitle="Files other people have shared with you" />
      {error && <div className="alert alert-danger">{error}</div>}

      <div className="card shadow-sm">
        <div className="table-responsive">
          <table className="table align-middle mb-0">
            <thead className="table-light">
              <tr><th>Name</th><th>Owner</th><th>Permission</th><th>Risk</th><th>Shared</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={6} className="text-center py-4 text-muted">Loading...</td></tr>}
              {!loading && files.length === 0 && <tr><td colSpan={6} className="text-center py-4 text-muted">Nothing has been shared with you yet.</td></tr>}
              {files.map((f) => (
                <tr key={f.id}>
                  <td>{f.originalName} <small className="text-muted">({formatBytes(f.fileSize)})</small></td>
                  <td>{f.ownerName} <small className="text-muted">{f.ownerEmail}</small></td>
                  <td><span className="badge text-bg-info">{f.permission}</span></td>
                  <td><RiskBadge level={f.riskLevel} /></td>
                  <td className="small">{formatDate(f.sharedAt)}</td>
                  <td>
                    {f.permission === 'VIEW' ? (
                      <span className="small text-muted">View only</span>
                    ) : (
                      <button className="btn btn-sm btn-outline-primary" disabled={busyId === f.id} onClick={() => handleDownload(f)}>Download</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {stepUpFile && (
        <StepUpModal
          riskLevel={stepUpFile.riskLevel}
          onVerified={() => { const f = stepUpFile; setStepUpFile(null); handleDownload(f); }}
          onCancel={() => setStepUpFile(null)}
        />
      )}
    </>
  );
}