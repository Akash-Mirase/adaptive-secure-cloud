import { useEffect, useState } from 'react';
import * as fileService from '../services/fileService.js';

export default function RiskBreakdownModal({ fileId, onClose }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    fileService.getRiskBreakdown(fileId).then(setData).catch((e) => setError(e.message));
  }, [fileId]);

  return (
    <div className="modal d-block" style={{ background: 'rgba(0,0,0,0.5)' }} onClick={onClose}>
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">Risk score breakdown</h5>
            <button className="btn-close" onClick={onClose} />
          </div>
          <div className="modal-body">
            {error && <div className="alert alert-danger">{error}</div>}
            {!data && !error && <p className="text-muted">Loading...</p>}
            {data && (
              <ul className="list-group">
                <li className="list-group-item d-flex justify-content-between"><span>File type</span><span>{data.fileTypeScore}</span></li>
                <li className="list-group-item d-flex justify-content-between"><span>Sensitive keywords</span><span>{data.keywordScore}</span></li>
                <li className="list-group-item d-flex justify-content-between"><span>Your declared sensitivity</span><span>{data.userSensitivityScoreImplied}</span></li>
                <li className="list-group-item d-flex justify-content-between fw-semibold"><span>Total</span><span>{data.riskScore} → {data.riskLevel}</span></li>
                {data.keywordMatches.length > 0 && (
                  <li className="list-group-item">
                    <div className="small text-muted mb-1">Matched keywords in filename:</div>
                    {data.keywordMatches.map((m) => (
                      <span key={m.pattern} className="badge text-bg-warning me-1">{m.pattern} (+{m.weight})</span>
                    ))}
                  </li>
                )}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}