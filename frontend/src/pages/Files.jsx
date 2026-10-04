import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import PageHeader from '../components/PageHeader.jsx'
import RiskBadge from '../components/RiskBadge.jsx'
import * as fileService from '../services/fileService.js'
import { formatBytes, formatDate } from '../utils/format.js'
import RiskBreakdownModal from '../components/RiskBreakdownModal.jsx'
import StepUpModal from '../components/StepUpModal.jsx'
import { parseApiError, isStepUpRequired } from '../utils/apiError.js';

export default function Files () {
  const [files, setFiles] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [busyId, setBusyId] = useState(null)
  const [detailsId, setDetailsId] = useState(null)
  const [stepUpFile, setStepUpFile] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      setFiles(await fileService.listFiles())
      setError('')
    } catch (err) {
      setError(parseApiError(err).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const handleDownload = async file => {
    setBusyId(file.id)
    setError('')

    try {
      await fileService.downloadFile(file.id, file.originalName, file.mimeType)
    } catch (err) {
      if (isStepUpRequired(err)) {
        setStepUpFile(file)
      } else {
        setError(parseApiError(err).message)
      }
    } finally {
      setBusyId(null)
    }
  }

  const handleStepUpVerified = async () => {
    const file = stepUpFile

    setStepUpFile(null)

    if (!file) return

    await handleDownload(file)
  }

  const handleDelete = async file => {
    if (
      !window.confirm(`Delete "${file.originalName}"? This cannot be undone.`)
    )
      return
    setBusyId(file.id)
    try {
      await fileService.deleteFile(file.id)
      setFiles(prev => prev.filter(f => f.id !== file.id))
    } catch (err) {
      setError(parseApiError(err).message)
    } finally {
      setBusyId(null)
    }
  }

  return (
    <>
      <PageHeader title='My Files' subtitle='Files you own'>
        <Link to='/upload' className='btn btn-primary'>
          Upload file
        </Link>
      </PageHeader>

      {error && <div className='alert alert-danger'>{error}</div>}

      <div className='alert alert-info small'>
        Your encryption keys unlock automatically when you log in. If you reload
        the page, you will be asked to re-enter your password once to unlock
        them again for this tab.
      </div>

      <div className='card shadow-sm'>
        <div className='table-responsive'>
          <table className='table table-hover align-middle mb-0'>
            <thead className='table-light'>
              <tr>
                <th>Name</th>
                <th>Size</th>
                <th>Type</th>
                <th>Risk</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={7} className='text-center py-4 text-muted'>
                    Loading...
                  </td>
                </tr>
              )}
              {!loading && files.length === 0 && (
                <tr>
                  <td colSpan={7} className='text-center py-4 text-muted'>
                    No files yet. Upload one to get started.
                  </td>
                </tr>
              )}
              {files.map(f => (
                <tr key={f.id}>
                  <td>{f.originalName}</td>
                  <td>{formatBytes(f.fileSize)}</td>
                  <td className='small text-muted'>{f.mimeType}</td>
                  <td>
                    <RiskBadge level={f.riskLevel} />{' '}
                    <small className='text-muted'>({f.riskScore})</small>
                    {(f.riskLevel === 'HIGH' || f.riskLevel === 'CRITICAL') && (
                      <span
                        className='ms-1'
                        title='Requires step-up verification to open'
                      >
                        🔒
                      </span>
                    )}
                  </td>
                  <td>
                    <span
                      className={`badge text-bg-${
                        f.encryptionPending ? 'secondary' : 'success'
                      }`}
                    >
                      {f.encryptionPending
                        ? 'Not encrypted'
                        : `Encrypted (${f.encryptionAlgorithm})`}
                    </span>
                  </td>
                  <td className='small'>{formatDate(f.createdAt)}</td>
                  <td className='text-nowrap'>
                    <button
                      className='btn btn-sm btn-outline-primary me-1'
                      disabled={busyId === f.id}
                      onClick={() => handleDownload(f)}
                    >
                      Download
                    </button>

                    <button
                      className='btn btn-sm btn-outline-secondary me-1'
                      disabled
                    >
                      Share
                    </button>

                    <button
                      className='btn btn-sm btn-outline-dark me-1'
                      onClick={() => setDetailsId(f.id)}
                    >
                      Details
                    </button>

                    <button
                      className='btn btn-sm btn-outline-danger'
                      disabled={busyId === f.id}
                      onClick={() => handleDelete(f)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {detailsId && (
        <RiskBreakdownModal
          fileId={detailsId}
          onClose={() => setDetailsId(null)}
        />
      )}
      {stepUpFile && (
        <StepUpModal
          riskLevel={stepUpFile.riskLevel}
          onVerified={handleStepUpVerified}
          onCancel={() => {
            setStepUpFile(null)
          }}
        />
      )}
    </>
  )
}
