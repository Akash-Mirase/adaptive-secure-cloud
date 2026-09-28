import { useEffect, useState } from 'react';
import api from '../services/api.js';

export default function Home() {
  const [backend, setBackend] = useState({ state: 'checking', detail: '' });

  // Web Crypto only works in a "secure context" (HTTPS or localhost).
  const cryptoAvailable =
    typeof window !== 'undefined' &&
    window.isSecureContext &&
    !!window.crypto?.subtle;

  useEffect(() => {
    api
      .get('/health')
      .then((res) =>
        setBackend({ state: 'ok', detail: `${res.data.data.service} (uptime ${res.data.data.uptimeSeconds}s)` })
      )
      .catch((err) => setBackend({ state: 'down', detail: err.message }));
  }, []);

  const badge = (ok) => (ok ? 'success' : 'danger');

  return (
    <div className="container py-5">
      <h1 className="mb-1">Adaptive Secure Cloud Storage</h1>
      <p className="text-muted">Client-Side Encryption and Risk-Based Key Management</p>

      <div className="card mt-4">
        <div className="card-header fw-semibold">System Status (Phase 1)</div>
        <ul className="list-group list-group-flush">
          <li className="list-group-item d-flex justify-content-between">
            <span>React frontend</span>
            <span className="badge text-bg-success">running</span>
          </li>
          <li className="list-group-item d-flex justify-content-between">
            <span>Backend API {backend.detail && <small className="text-muted">— {backend.detail}</small>}</span>
            <span
              className={`badge text-bg-${
                backend.state === 'checking' ? 'secondary' : badge(backend.state === 'ok')
              }`}
            >
              {backend.state}
            </span>
          </li>
          <li className="list-group-item d-flex justify-content-between">
            <span>Web Crypto API (window.crypto.subtle)</span>
            <span className={`badge text-bg-${badge(cryptoAvailable)}`}>
              {cryptoAvailable ? 'available' : 'unavailable'}
            </span>
          </li>
        </ul>
      </div>
    </div>
  );
}