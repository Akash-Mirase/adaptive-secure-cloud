import { useEffect, useState } from 'react';
import PageHeader from '../components/PageHeader.jsx';
import StatCard from '../components/StatCard.jsx';
import * as fileService from '../services/fileService.js';

export default function Security() {
  const [files, setFiles] = useState([]);
  useEffect(() => { fileService.listFiles().then(setFiles).catch(() => {}); }, []);

  const count = (level) => files.filter((f) => f.riskLevel === level).length;

  return (
    <>
      <PageHeader title="Security" subtitle="Live risk distribution across your files" />
      <div className="row g-3 mb-4">
        <div className="col-6 col-lg-3"><StatCard label="Encrypted files" value={files.length} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Low risk" value={count('LOW')} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Medium risk" value={count('MEDIUM')} /></div>
        <div className="col-6 col-lg-3"><StatCard label="High risk" value={count('HIGH')} /></div>
        <div className="col-6 col-lg-3"><StatCard label="Critical risk" value={count('CRITICAL')} /></div>
      </div>
      <div className="card shadow-sm">
        <div className="card-header fw-semibold">Encryption status</div>
        <ul className="list-group list-group-flush">
          <li className="list-group-item d-flex justify-content-between"><span>Cipher</span><span>AES-256-GCM</span></li>
          <li className="list-group-item d-flex justify-content-between"><span>Encryption location</span><span>Browser (client-side)</span></li>
          <li className="list-group-item d-flex justify-content-between"><span>Risk classification</span><span>Server-side, rule-based, transparent</span></li>
        </ul>
      </div>
    </>
  );
}