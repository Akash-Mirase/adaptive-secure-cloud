
import { useState } from 'react'
import { Link } from 'react-router-dom'
import PageHeader from '../components/PageHeader.jsx'
import RiskBadge from '../components/RiskBadge.jsx'
import * as fileService from '../services/fileService.js'
import { parseApiError } from '../utils/apiError.js'
import { formatBytes } from '../utils/format.js'

const STAGE_LABEL = {
  idle: 'Not started',
  inspecting: 'Inspecting file locally in your browser...',
  encrypting: 'Encrypting in your browser (AES-256-GCM)...',
  uploading: 'Uploading ciphertext and safe evidence...',
  done: 'Complete',
  error: 'Failed'
}

// Categories and their minimum sensitivity levels
const FILE_CATEGORIES = {
  general: {
    label: 'General documents',
    sensitivity: 0,
    description: 'Ordinary documents and public information.'
  },
  images: {
    label: 'Images / Photographs',
    sensitivity: 1,
    description: 'Images may be public or personal. Confirm whether they contain private content.'
  },
  financial: {
    label: 'Financial records',
    sensitivity: 3,
    description: 'Bank statements, invoices, payment records and financial documents.'
  },
  identity: {
    label: 'Identity documents',
    sensitivity: 4,
    description: 'Aadhaar, PAN, passport and other identity documents.'
  },
  medical: {
    label: 'Medical records',
    sensitivity: 4,
    description: 'Medical reports, prescriptions and health-related documents.'
  },
  credentials: {
    label: 'Credentials and keys',
    sensitivity: 4,
    description: 'API keys, passwords, private keys and configuration secrets.'
  },
  business: {
    label: 'Business documents',
    sensitivity: 3,
    description: 'Internal reports, confidential business and company documents.'
  }
}

// Initial suggestion based on filename and file type.
// This is a heuristic, not proof of the file's actual contents.
function suggestCategory(file) {
  if (!file) return 'general'

  const name = file.name.toLowerCase()
  const type = file.type.toLowerCase()

  if (
    /aadhaar|aadhar|pan.?card|passport|identity|voter.?id|driving.?licen[cs]e/.test(name)
  ) return 'identity'

  if (
    /medical|health|prescription|diagnosis|lab.?report|patient/.test(name)
  ) return 'medical'

  if (
    /bank|statement|invoice|payment|transaction|salary|tax|financial/.test(name)
  ) return 'financial'

  if (
    /private.?key|secret|credential|password|token|api.?key|\.env|id_rsa|\.pem|\.key/.test(name)
  ) return 'credentials'

  if (
    /business|company|corporate|internal|confidential|project.?report/.test(name)
  ) return 'business'

  if (
    type.startsWith('image/') ||
    /\.(png|jpe?g|webp|gif|bmp)$/.test(name)
  ) return 'images'

  return 'general'
}

export default function Upload() {
  const [file, setFile] = useState(null)
  const [category, setCategory] = useState('general')
  const [sensitivity, setSensitivity] = useState(1)
  const [progress, setProgress] = useState(0)
  const [stage, setStage] = useState('idle')
  const [error, setError] = useState('')
  const [uploaded, setUploaded] = useState(null)
  const [personalImage, setPersonalImage] = useState(false)

  const isProcessing = ['inspecting', 'encrypting', 'uploading'].includes(stage)

  const handleSelect = (e) => {
    const selectedFile = e.target.files?.[0] || null

    setFile(selectedFile)
    setCategory(suggestCategory(selectedFile))
    setStage('idle')
    setUploaded(null)
    setError('')
    setProgress(0)
    setPersonalImage(false)
  }

  const handleCategoryChange = (e) => {
    setCategory(e.target.value)
    setUploaded(null)
  }

  const isImage = file && (
    file.type.startsWith('image/') ||
    /\.(png|jpe?g|webp|gif|bmp)$/i.test(file.name)
  )

  // Category and user declaration establish minimum sensitivity.
  // A user's higher sensitivity selection is always preserved.
  const categorySensitivity = FILE_CATEGORIES[category]?.sensitivity ?? 0

  const effectiveSensitivity = Math.max(
    sensitivity,
    categorySensitivity,
    personalImage ? 2 : 0
  )

  const handleUpload = async () => {
    if (!file) return

    setError('')
    setProgress(0)

    try {
      const result = await fileService.uploadFile(file, {
        onStageChange: setStage,
        onProgress: setProgress,
        userSensitivity: effectiveSensitivity
      })

      setUploaded(result)
      setStage('done')
    } catch (err) {
      setError(parseApiError(err).message)
      setStage('error')
    }
  }

  return (
    <>
      <PageHeader
        title="Secure File Upload"
        subtitle="Select your file, confirm its privacy category, and securely upload it."
      />

      {error && <div className="alert alert-danger small">{error}</div>}

      <div className="card shadow-sm" style={{ maxWidth: 680 }}>
        <div className="card-body">

          {/* File selection */}
          <div className="mb-3">
            <label className="form-label" htmlFor="file">
              Choose a file
            </label>

            <input
              id="file"
              type="file"
              className="form-control"
              onChange={handleSelect}
              disabled={isProcessing}
            />
          </div>

          {/* Automatic category suggestion and user confirmation */}
          {file && (
            <div className="mb-3 p-3 border rounded">
              <label className="form-label fw-semibold" htmlFor="category">
                What type of file are you uploading?
              </label>

              <select
                id="category"
                className="form-select"
                value={category}
                onChange={handleCategoryChange}
                disabled={isProcessing}
              >
                {Object.entries(FILE_CATEGORIES).map(([key, item]) => (
                  <option key={key} value={key}>
                    {item.label}
                  </option>
                ))}
              </select>

              <div className="form-text mt-2">
                Suggested category: {FILE_CATEGORIES[category].label}.
                Please verify that this category correctly describes your file.
              </div>

              <div className="alert alert-info small mt-2 mb-0">
                {FILE_CATEGORIES[category].description}
              </div>
            </div>
          )}

          {/* User sensitivity */}
          <div className="mb-3">
            <label className="form-label" htmlFor="sens">
              Your sensitivity rating
            </label>

            <select
              id="sens"
              className="form-select"
              value={sensitivity}
              onChange={e => setSensitivity(Number(e.target.value))}
              disabled={isProcessing}
            >
              <option value={0}>0: Public</option>
              <option value={1}>1: Normal</option>
              <option value={2}>2: Personal</option>
              <option value={3}>3: Confidential</option>
              <option value={4}>4: Highly Confidential</option>
            </select>

            <div className="form-text">
              The selected category establishes a minimum sensitivity.
              Your higher sensitivity selection is always preserved.
            </div>

            {file && (
              <div className="mt-2 small">
                **Effective minimum sensitivity:**{' '}
                <strong>
                  {effectiveSensitivity}: {
                    ['Public', 'Normal', 'Personal', 'Confidential', 'Highly Confidential'][effectiveSensitivity]
                  }
                </strong>
              </div>
            )}
          </div>

          {/* Personal image declaration */}
          {isImage && (
            <div className="mb-3 p-3 border rounded">
              <div className="form-check">
                <input
                  id="personalImage"
                  type="checkbox"
                  className="form-check-input"
                  checked={personalImage}
                  onChange={e => setPersonalImage(e.target.checked)}
                  disabled={isProcessing}
                />

                <label className="form-check-label" htmlFor="personalImage">
                  This image contains personal or private content
                </label>
              </div>

              <div className="form-text">
                Select this for personal photographs, family pictures,
                identity images or other private visual content.
              </div>
            </div>
          )}

          {/* File details */}
          {file && (
            <ul className="list-group mb-3">
              <li className="list-group-item d-flex justify-content-between">
                <span>File name</span>
                <span className="text-break ms-3">{file.name}</span>
              </li>

              <li className="list-group-item d-flex justify-content-between">
                <span>File size</span>
                <span>{formatBytes(file.size)}</span>
              </li>

              <li className="list-group-item d-flex justify-content-between">
                <span>File category</span>
                <span>{FILE_CATEGORIES[category].label}</span>
              </li>

              <li className="list-group-item d-flex justify-content-between">
                <span>Encryption</span>
                <span>AES-256-GCM</span>
              </li>

              <li className="list-group-item d-flex justify-content-between">
                <span>Inspection</span>
                <span>Browser-side content inspection</span>
              </li>

              <li className="list-group-item d-flex justify-content-between">
                <span>Upload status</span>
                <span>
                  {STAGE_LABEL[stage] || stage}
                  {stage === 'uploading' ? ` (${progress}%)` : ''}
                </span>
              </li>
            </ul>
          )}

          {/* Progress */}
          {isProcessing && (
            <div className="mb-3">
              <div className="progress" style={{ height: 10 }}>
                <div
                  className="progress-bar"
                  style={{
                    width: stage === 'uploading' ? `${progress}%` : '100%'
                  }}
                />
              </div>
            </div>
          )}

          {/* Upload button */}
          {!uploaded && (
            <button
              className="btn btn-primary"
              disabled={!file || isProcessing}
              onClick={handleUpload}
            >
              {isProcessing ? 'Processing...' : 'Inspect, Encrypt and Upload'}
            </button>
          )}

          {/* Upload result */}
          {uploaded && (
            <div className="alert alert-success mt-3">
              <div className="d-flex justify-content-between align-items-center mb-2">
                <span>
                  Uploaded <strong>{uploaded.originalName}</strong>
                </span>

                <RiskBadge level={uploaded.riskLevel} />
              </div>

              <div className="small">
                Risk score: <strong>{uploaded.riskScore}</strong> / 20
                {' · '}
                Level: <strong>{uploaded.riskLevel}</strong>
              </div>

              <div className="small font-monospace mt-2">
                Algorithm: {uploaded.encryptionAlgorithm}
                <br />
                Plaintext size: {formatBytes(uploaded.fileSize)}
                {' · '}
                Ciphertext size: {formatBytes(uploaded.encryptedSize)}
              </div>

              <Link to="/files" className="btn btn-sm btn-outline-success mt-2">
                Go to My Files
              </Link>
            </div>
          )}

        </div>
      </div>
    </>
  )
}
