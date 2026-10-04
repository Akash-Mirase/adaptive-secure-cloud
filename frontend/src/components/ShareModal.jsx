import { useEffect, useState } from 'react';
import * as fileService from '../services/fileService.js';
import { parseApiError, isStepUpRequired } from '../utils/apiError.js';
import StepUpModal from './StepUpModal.jsx';

const PERMISSION_LABELS = { VIEW: 'View details only', DOWNLOAD: 'View and download', EDIT: 'View, download, and replace (reupload not yet implemented)' };
const PERMISSION_ORDER = { VIEW: 0, DOWNLOAD: 1, EDIT: 2 };

export default function ShareModal({ file, onClose }) {
  const [policy, setPolicy] = useState(null);
  const [permissions, setPermissions] = useState([]);
  const [email, setEmail] = useState('');
  const [permission, setPermission] = useState('VIEW');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [needsStepUp, setNeedsStepUp] = useState(false);

  const load = async () => {
    const [risk, perms] = await Promise.all([fileService.getRiskBreakdown(file.id), fileService.getPermissions(file.id)]);
    setPolicy(risk.policy);
    setPermissions(perms.filter((p) => p.permission !== 'OWNER'));
    const allowed = Object.keys(PERMISSION_ORDER).filter((p) => PERMISSION_ORDER[p] <= PERMISSION_ORDER[risk.policy.maxSharePermission] ?? 0);
    setPermission(allowed[0] || 'VIEW');
  };

  useEffect(() => { load().catch((e) => setError(parseApiError(e).message)); }, [file.id]);

  const allowedPermissions = policy
    ? Object.keys(PERMISSION_LABELS).filter((p) => PERMISSION_ORDER[p] <= PERMISSION_ORDER[policy.maxSharePermission])
    : [];

  const doShare = async () => {
    setError('');
    setBusy(true);
    try {
      await fileService.shareFile(file.id, email, permission);
      setEmail('');
      await load();
    } catch (err) {
      if (isStepUpRequired(err)) {
        setNeedsStepUp(true);
      } else {
        setError(parseApiError(err).message);
      }
    } finally {
      setBusy(false);
    }
  };

  const handleRevoke = async (userId) => {
    try {
      await fileService.revokeShare(file.id, userId);
      setPermissions((prev) => prev.filter((p) => p.userId !== userId));
    } catch (err) {
      setError(parseApiError(err).message);
    }
  };

  return (
    <div className="modal d-block" style={{ background: 'rgba(0,0,0,0.5)' }} onClick={onClose}>
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">Share "{file.originalName}"</h5>
            <button className="btn-close" onClick={onClose} />
          </div>
          <div className="modal-body">
            {policy?.blockPublicSharing && (
              <div className="alert alert-warning small">This file is CRITICAL risk: it can only be shared VIEW-only, and never publicly.</div>
            )}
            {error && <div className="alert alert-danger py-2 small">{error}</div>}

            <div className="row g-2 mb-3">
              <div className="col-7">
                <input type="email" className="form-control" placeholder="Recipient's email"
                  value={email} onChange={(e) => setEmail(e.target.value)} />
              </div>
              <div className="col-3">
                <select className="form-select" value={permission} onChange={(e) => setPermission(e.target.value)}>
                  {allowedPermissions.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
              <div className="col-2">
                <button className="btn btn-primary w-100" disabled={!email || busy} onClick={doShare}>Share</button>
              </div>
            </div>
            <div className="form-text mb-3">{PERMISSION_LABELS[permission]}</div>

            <h6 className="small text-uppercase text-muted">Currently shared with</h6>
            {permissions.length === 0 && <p className="small text-muted">No one yet.</p>}
            <ul className="list-group">
              {permissions.map((p) => (
                <li key={p.userId} className="list-group-item d-flex justify-content-between align-items-center">
                  <span>{p.name} <small className="text-muted">({p.email})</small> — <span className="badge text-bg-info">{p.permission}</span></span>
                  <button className="btn btn-sm btn-outline-danger" onClick={() => handleRevoke(p.userId)}>Revoke</button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {needsStepUp && (
        <StepUpModal
          riskLevel={file.riskLevel}
          onVerified={() => { setNeedsStepUp(false); doShare(); }}
          onCancel={() => setNeedsStepUp(false)}
        />
      )}
    </div>
  );
}