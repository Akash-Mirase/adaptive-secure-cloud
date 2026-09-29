import { useState } from 'react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import RiskBadge from '../components/RiskBadge.jsx';
import * as fileService from '../services/fileService.js';
import { parseApiError } from '../utils/apiError.js';
import { formatBytes } from '../utils/format.js';

const STAGE_LABEL = {
  idle: 'Not started',
  encrypting: 'Encrypting in your browser (AES-256-GCM)...',
  uploading: 'Uploading ciphertext...',
  done: 'Complete',
  error: 'Failed',
};

export default function Upload() {
  const [file, setFile] = useState(null);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState('idle');
  const [error, setError] = useState('');
  const [uploaded, setUploaded] = useState(null);

  const handleSelect = (e) => {
    setFile(e.target.files[0] || null);
    setStage('idle');
    setUploaded(null);
    setError('');
  };

  const handleUpload = async () => {
    if (!file) return;
    setError('');
    setProgress(0);
    try {
      const result = await fileService.uploadFile(file, {
        onStageChange: setStage,
        onProgress: setProgress,
      });
      setUploaded(result);
      setStage('done');
    } catch (err) {
      setError(parseApiError(err).message);
      setStage('error');
    }
  };

  return (
    <>
      <PageHeader title="Upload" subtitle="Your file is encrypted in this browser before anything is sent." />

      {error && <div className="alert alert-danger small">{error}</div>}

      <div className="card shadow-sm" style={{ maxWidth: 640 }}>
        <div className="card-body">
          <div className="mb-3">
            <label className="form-label" htmlFor="file">Choose a file</label>
            <input id="file" type="file" className="form-control" onChange={handleSelect} disabled={stage === 'encrypting' || stage === 'uploading'} />
          </div>

          {file && (
            <ul className="list-group mb-3">
              <li className="list-group-item d-flex justify-content-between"><span>File name</span><span>{file.name}</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>File size</span><span>{formatBytes(file.size)}</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Risk score / level</span><span className="text-muted">Phase 10</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Encryption</span><span>AES-256-GCM, unique key + IV per file</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Upload status</span><span>{STAGE_LABEL[stage]}{stage === 'uploading' ? ` (${progress}%)` : ''}</span></li>
            </ul>
          )}

          {(stage === 'uploading') && (
            <div className="progress mb-3" style={{ height: 10 }}>
              <div className="progress-bar" style={{ width: `${progress}%` }} />
            </div>
          )}

          {!uploaded && (
            <button className="btn btn-primary" disabled={!file || stage === 'encrypting' || stage === 'uploading'} onClick={handleUpload}>
              {stage === 'encrypting' || stage === 'uploading' ? 'Working...' : 'Encrypt and upload'}
            </button>
          )}

          {uploaded && (
            <div className="alert alert-success mt-3">
              <div className="d-flex justify-content-between align-items-center mb-2">
                <span>Uploaded <strong>{uploaded.originalName}</strong></span>
                <RiskBadge level={uploaded.riskLevel} />
              </div>
              <div className="small font-monospace">
                Algorithm: {uploaded.encryptionAlgorithm}<br />
                IV (base64, not secret): {uploaded.iv}<br />
                Plaintext size: {formatBytes(uploaded.fileSize)} · Ciphertext size: {formatBytes(uploaded.encryptedSize)}
              </div>
              <Link to="/files" className="btn btn-sm btn-outline-success mt-2">Go to My Files</Link>
            </div>
          )}
        </div>
      </div>
    </>
  );
}