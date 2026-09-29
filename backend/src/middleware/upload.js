import multer from 'multer';
import AppError from '../utils/AppError.js';
import { env } from '../config/env.js';

const MAX_FILE_SIZE_BYTES = env.maxUploadMb * 1024 * 1024;

// First-line filter by MIME type. This is a coarse check, not a substitute
// for virus scanning; it exists to reject obviously wrong content
// (executables, scripts) early. 'application/octet-stream' is allowed because
// from Phase 7 onward every upload IS ciphertext, which browsers report as
// this generic type.
const ALLOWED_MIME_TYPES = new Set([
  'application/pdf', 'text/plain', 'text/csv',
  'image/png', 'image/jpeg', 'image/gif', 'image/webp',
  'application/zip',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/msword', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint',
  'application/octet-stream',
]);

const upload = multer({
  storage: multer.memoryStorage(), // held in RAM only; Phase 7 encrypts this buffer before it is ever written anywhere
  limits: { fileSize: MAX_FILE_SIZE_BYTES, files: 1 },
  fileFilter(req, file, cb) {
    if (!ALLOWED_MIME_TYPES.has(file.mimetype)) {
      return cb(new AppError(`File type not allowed: ${file.mimetype}`, 415));
    }
    cb(null, true);
  },
});

// Wraps multer so its errors go through OUR error handler (standard JSON
// envelope) instead of an uncaught exception or a raw multer error.
export function uploadSingleFile(req, res, next) {
  upload.single('file')(req, res, (err) => {
    if (!err) return next();
    if (err.code === 'LIMIT_FILE_SIZE') {
      return next(new AppError(`File exceeds the ${env.maxUploadMb} MB limit`, 413));
    }
    return next(err);
  });
}