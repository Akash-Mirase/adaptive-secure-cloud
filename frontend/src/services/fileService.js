import api from './api.js'
import {
  encryptFileForUpload,
  decryptDownloadedFile
} from '../crypto/fileCrypto.js'
import { getMasterKey } from '../crypto/masterKeySession.js'
import { getStepUpToken } from '../utils/stepUpSession.js'

function requireMasterKey () {
  const key = getMasterKey()
  if (!key)
    throw new Error(
      'Your keys are locked in this tab. Please unlock and try again.'
    )
  return key
}

export async function uploadFile (
  file,
  { onProgress, onStageChange, userSensitivity = 0 } = {}
) {
  const masterKey = requireMasterKey()
  onStageChange?.('encrypting')
  const enc = await encryptFileForUpload(file, masterKey)
  onStageChange?.('uploading')

  const formData = new FormData()
  formData.append('file', enc.ciphertextBlob, enc.originalName)
  formData.append('iv', enc.ivBase64)
  formData.append('keyMetadata', JSON.stringify(enc.keyMetadata))
  formData.append('mimeType', enc.originalMimeType)
  formData.append('originalSize', String(enc.originalSize))
  formData.append('wrappedFek', enc.wrappedFekBase64)
  formData.append('wrapIv', enc.wrapIvBase64)
  formData.append('userSensitivity', String(userSensitivity)) // drives server-side risk scoring, Phase 10

  const res = await api.post('/files', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: evt => {
      if (evt.total) onProgress?.(Math.round((evt.loaded / evt.total) * 100))
    }
  })
  return res.data.data.file
}

export async function getRiskBreakdown (id) {
  const res = await api.get(`/files/${id}/risk`)
  return res.data.data
}

export async function listFiles () {
  const res = await api.get('/files')
  return res.data.data.files
}

export async function downloadFile (id, filename, mimeType) {
  const masterKey = requireMasterKey()
  const stepUpToken = getStepUpToken()

  const keyConfig = stepUpToken
    ? {
        headers: {
          Authorization: `Bearer ${stepUpToken}`
        }
      }
    : {}

  const { data: meta } = await api.get(`/files/${id}`)

  const { data: keyRes } = await api.get(`/files/${id}/key`)
  const iv = meta.data.file.iv
  const { wrappedFek, wrapIv } = keyRes.data

  const { data: ciphertext } = await api.get(`/files/${id}/download`, {
    responseType: 'arraybuffer'
  })
  const blob = await decryptDownloadedFile(
    ciphertext,
    iv,
    wrappedFek,
    wrapIv,
    masterKey,
    mimeType
  ) // throws on tampering / wrong key

  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export async function deleteFile (id) {
  await api.delete(`/files/${id}`)
}
