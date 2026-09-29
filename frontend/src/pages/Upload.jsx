import { useState } from 'react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import RiskBadge from '../components/RiskBadge.jsx';
import * as fileService from '../services/fileService.js';
import { parseApiError } from '../utils/apiError.js';
import { formatBytes } from '../utils/format.js';

export default function Upload() {
  const [file, setFile] = useState(null);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('idle'); // idle | uploading | done | error
  const [error, setError] = useState('');
  const [uploaded, setUploaded] = useState(null);

  const handleSelect = (e) => {
    setFile(e.target.files[0] || null);
    setStatus('idle');
    setUploaded(null);
    setError('');
  };

  const handleUpload = async () => {
    if (!file) return;
    setStatus('uploading');
    setProgress(0);
    setError('');
    try {
      const result = await fileService.uploadFile(file, { onProgress: setProgress });
      setUploaded(result);
      setStatus('done');
    } catch (err) {
      setError(parseApiError(err).message);
      setStatus('error');
    }
  };

  return (
    <>
      <PageHeader title="Upload" subtitle="Files will be encrypted in your browser before upload, starting Phase 7." />

      <div className="alert alert-warning small">
        Phase 6: this uploads the file as-is (no encryption yet), to prove the storage pipeline works.
        Encryption is added in Phase 7 and will change nothing about how you use this page.
      </div>

      {error && <div className="alert alert-danger small">{error}</div>}

      <div className="card shadow-sm" style={{ maxWidth: 640 }}>
        <div className="card-body">
          <div className="mb-3">
            <label className="form-label" htmlFor="file">Choose a file</label>
            <input id="file" type="file" className="form-control" onChange={handleSelect} disabled={status === 'uploading'} />
          </div>

          {file && (
            <ul className="list-group mb-3">
              <li className="list-group-item d-flex justify-content-between"><span>File name</span><span>{file.name}</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>File size</span><span>{formatBytes(file.size)}</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Risk score / level</span><span className="text-muted">Phase 10</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Encryption status</span><span className="text-muted">Phase 7</span></li>
              <li className="list-group-item d-flex justify-content-between">
                <span>Upload status</span>
                <span>{status === 'idle' ? 'Not started' : status === 'uploading' ? `${progress}%` : status === 'done' ? 'Complete' : 'Failed'}</span>
              </li>
            </ul>
          )}

          {status === 'uploading' && (
            <div className="progress mb-3" style={{ height: 10 }}>
              <div className="progress-bar" style={{ width: `${progress}%` }} />
            </div>
          )}

          {!uploaded && (
            <button className="btn btn-primary" disabled={!file || status === 'uploading'} onClick={handleUpload}>
              {status === 'uploading' ? 'Uploading...' : 'Upload'}
            </button>
          )}

          {uploaded && (
            <div className="alert alert-success mt-3">
              <div className="d-flex justify-content-between align-items-center">
                <span>Uploaded <strong>{uploaded.originalName}</strong></span>
                <RiskBadge level={uploaded.riskLevel} />
              </div>
              <Link to="/files" className="btn btn-sm btn-outline-success mt-2">Go to My Files</Link>
            </div>
          )}
        </div>
      </div>
    </>
  );
}