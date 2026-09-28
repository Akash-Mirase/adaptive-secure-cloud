import { useState } from 'react';
import PageHeader from '../components/PageHeader.jsx';
import { formatBytes } from '../utils/format.js';

export default function Upload() {
  const [file, setFile] = useState(null);
  const [sensitivity, setSensitivity] = useState(1);

  return (
    <>
      <PageHeader title="Upload" subtitle="Files will be encrypted in your browser before upload." />

      <div className="alert alert-warning small">
        Phase 2: file selection only. Risk analysis, encryption, and upload are added in later phases.
        Nothing is read or sent.
      </div>

      <div className="card shadow-sm" style={{ maxWidth: 640 }}>
        <div className="card-body">
          <div className="mb-3">
            <label className="form-label" htmlFor="file">Choose a file</label>
            <input id="file" type="file" className="form-control" onChange={(e) => setFile(e.target.files[0] || null)} />
          </div>

          <div className="mb-3">
            <label className="form-label" htmlFor="sens">Your sensitivity rating</label>
            <select id="sens" className="form-select" value={sensitivity} onChange={(e) => setSensitivity(Number(e.target.value))}>
              <option value={0}>0: Public</option>
              <option value={1}>1: Normal</option>
              <option value={2}>2: Private</option>
              <option value={3}>3: Highly sensitive</option>
            </select>
          </div>

          {file && (
            <ul className="list-group mb-3">
              <li className="list-group-item d-flex justify-content-between"><span>File name</span><span>{file.name}</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>File size</span><span>{formatBytes(file.size)}</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Risk score / level</span><span className="text-muted">Phase 10</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Encryption status</span><span className="text-muted">Phase 7</span></li>
              <li className="list-group-item d-flex justify-content-between"><span>Upload status</span><span className="text-muted">Phase 6</span></li>
            </ul>
          )}

          <button className="btn btn-primary" disabled>Encrypt and upload</button>
        </div>
      </div>
    </>
  );
}