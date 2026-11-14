import { useState } from 'react'
import * as authService from '../services/authService.js'
import { setStepUpToken } from '../utils/stepUpSession.js'

// Shown when the server responds 428 to a HIGH/CRITICAL file action.
// This is password RE-CONFIRMATION, not multi-factor authentication — there
// is no second factor registered anywhere in this system. See the Phase 11
// scope note in the project report for the reasoning.
export default function StepUpModal ({ riskLevel, onVerified, onCancel }) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [code, setCode] = useState('')
  const [needsCode, setNeedsCode] = useState(false)

  const handleSubmit = async e => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      const extra =
        needsCode && code
          ? code.includes('-') || code.length > 6
            ? { recoveryCode: code }
            : { mfaCode: code }
          : {}
      const { stepUpToken } = await authService.requestStepUp(password, extra)
      setStepUpToken(stepUpToken)
      onVerified()
    } catch (err) {
      if (err.response?.status === 422) {
        setNeedsCode(true)
        setError(
          'Enter the code from your authenticator app (or a recovery code).'
        )
      } else setError(err.response?.data?.message || 'Verification failed.')
    }
  }

  return (
    <div
      className='modal d-block'
      style={{ background: 'rgba(0,0,0,0.5)' }}
      onClick={onCancel}
    >
      <div className='modal-dialog' onClick={e => e.stopPropagation()}>
        <div className='modal-content'>
          <div className='modal-header'>
            <h5 className='modal-title'>Confirm it's you</h5>
            <button className='btn-close' onClick={onCancel} />
          </div>
          <div className='modal-body'>
            <p className='small text-muted'>
              This file is classified <strong>{riskLevel}</strong> risk. Please
              re-enter your password to continue.
            </p>
            {error && (
              <div className='alert alert-danger py-2 small'>{error}</div>
            )}
            <form onSubmit={handleSubmit}>
              <input
                type='password'
                className='form-control mb-3'
                placeholder='Password'
                autoFocus
                autoComplete='current-password'
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
              />
              Add below the password input: jsx
              {needsCode && (
                <input
                  className='form-control mb-3 font-monospace'
                  placeholder='Authenticator or recovery code'
                  autoComplete='one-time-code'
                  value={code}
                  onChange={e => setCode(e.target.value)}
                  required
                />
              )}
              <button className='btn btn-primary w-100' disabled={busy}>
                {busy ? 'Verifying...' : 'Verify and continue'}
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  )
}
