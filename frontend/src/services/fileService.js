import api from './api.js';

export async function uploadFile(file, { onProgress } = {}) {
  const formData = new FormData();
  formData.append('file', file);
  const res = await api.post('/files', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (evt) => {
      if (evt.total) onProgress?.(Math.round((evt.loaded / evt.total) * 100));
    },
  });
  return res.data.data.file;
}

export async function listFiles() {
  const res = await api.get('/files');
  return res.data.data.files;
}

export async function downloadFile(id, filename) {
  const res = await api.get(`/files/${id}/download`, { responseType: 'blob' });
  const url = URL.createObjectURL(res.data);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function deleteFile(id) {
  await api.delete(`/files/${id}`);
}