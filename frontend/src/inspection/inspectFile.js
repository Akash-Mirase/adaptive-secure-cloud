
import { detectSensitivePatterns } from './patterns.js';
import { normalizeEvidence } from './normalize.js';

// Safety limits
const MAX_FILE_SIZE = 15 * 1024 * 1024; // 15 MB
const MAX_TEXT_LENGTH = 1_500_000;
const MAX_PDF_PAGES = 50;
const MAX_OCR_IMAGE_SIZE = 10 * 1024 * 1024;

// Supported file extensions
const TEXT_EXTENSIONS = ['txt', 'csv'];
const IMAGE_EXTENSIONS = ['png', 'jpg', 'jpeg', 'webp'];

function getExtension(filename) {
  return filename.split('.').pop()?.toLowerCase() || '';
}

function getInspectionStatus(text, partial = false) {
  if (!text.trim()) return 'PARTIAL';
  return partial ? 'PARTIAL' : 'COMPLETE';
}

// Extract text from TXT and CSV files
async function extractTextFile(file) {
  const text = await file.text();

  return {
    text: text.slice(0, MAX_TEXT_LENGTH),
    partial: text.length > MAX_TEXT_LENGTH,
  };
}

// Extract text from DOCX files
async function extractDocx(file) {
  const mammoth = await import('mammoth');

  const arrayBuffer = await file.arrayBuffer();

  const result = await mammoth.extractRawText({
    arrayBuffer,
  });

  return {
    text: result.value.slice(0, MAX_TEXT_LENGTH),
    partial: result.value.length > MAX_TEXT_LENGTH,
  };
}

// Extract text from PDF files
async function extractPdf(file) {
  const pdfjs = await import('pdfjs-dist');
  const workerUrl = await import(
    'pdfjs-dist/build/pdf.worker.min.mjs?url'
  );

  pdfjs.GlobalWorkerOptions.workerSrc = workerUrl.default;

  const arrayBuffer = await file.arrayBuffer();

  const pdf = await pdfjs.getDocument({
    data: new Uint8Array(arrayBuffer),
    isEvalSupported: false,
    useSystemFonts: true,
  }).promise;

  let extractedText = '';
  let partial = false;

  try {
    const pagesToRead = Math.min(pdf.numPages, MAX_PDF_PAGES);

    if (pdf.numPages > MAX_PDF_PAGES) {
      partial = true;
    }

    for (let pageNumber = 1; pageNumber <= pagesToRead; pageNumber++) {
      const page = await pdf.getPage(pageNumber);
      const content = await page.getTextContent();

      const pageText = content.items
        .filter((item) => typeof item.str === 'string')
        .map((item) => item.str)
        .join(' ');

      extractedText += pageText + '\n';

      if (extractedText.length >= MAX_TEXT_LENGTH) {
        extractedText = extractedText.slice(0, MAX_TEXT_LENGTH);
        partial = true;
        break;
      }
    }
  } finally {
    await pdf.destroy();
  }

  return {
    text: extractedText,
    partial,
  };
}

// OCR for image files
async function extractImageText(file) {
  if (file.size > MAX_OCR_IMAGE_SIZE) {
    return {
      text: '',
      partial: true,
      ocrUsed: true,
    };
  }

  const { createWorker } = await import('tesseract.js');

  const worker = await createWorker('eng');

  try {
    const result = await worker.recognize(file);

    const text = result.data.text || '';

    return {
      text: text.slice(0, MAX_TEXT_LENGTH),
      partial: text.length > MAX_TEXT_LENGTH,
      ocrUsed: true,
    };
  } finally {
    await worker.terminate();
  }
}

/**
 * Inspects a file locally in the browser.
 *
 * Returns only:
 * - evidence version
 * - inspection status
 * - detected categories and rule names
 * - strength and occurrence count
 *
 * Never returns extracted text or matched sensitive values.
 */
export async function inspectFile(file) {
  if (!file || typeof file.name !== 'string') {
    return normalizeEvidence({
      status: 'FAILED',
    });
  }

  if (file.size > MAX_FILE_SIZE) {
    return normalizeEvidence({
      status: 'TOO_LARGE',
    });
  }

  const extension = getExtension(file.name);

  let extractedText;
  let partial;
  let ocrUsed = false;

  try {
    if (TEXT_EXTENSIONS.includes(extension)) {
      const result = await extractTextFile(file);

      extractedText = result.text;
      partial = result.partial;
    } else if (extension === 'pdf') {
      const result = await extractPdf(file);

      extractedText = result.text;
      partial = result.partial;
    } else if (extension === 'docx') {
      const result = await extractDocx(file);

      extractedText = result.text;
      partial = result.partial;
    } else if (IMAGE_EXTENSIONS.includes(extension)) {
      const result = await extractImageText(file);

      extractedText = result.text;
      partial = result.partial;
      ocrUsed = result.ocrUsed;
    } else {
      return normalizeEvidence({
        status: 'UNSUPPORTED',
      });
    }

    // Run detection locally. Only counts and rule identifiers survive.
    const indicators = detectSensitivePatterns(extractedText);

    const status = getInspectionStatus(
      extractedText,
      partial
    );

    return normalizeEvidence({
      status,
      indicators,
      ocrUsed,
    });
  } catch {
    // Do not log file content or extracted text.
    return normalizeEvidence({
      status: 'FAILED',
      ocrUsed,
    });
  }
}
