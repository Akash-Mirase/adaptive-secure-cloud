import api from './api.js';

export async function getMyLogs(params = {}) {
  const res = await api.get('/audit/me', { params });
  return res.data.data; // { logs, total, page, pageSize }
}
export async function getMyStats() {
  const res = await api.get('/audit/me/stats');
  return res.data.data; // { byEventType, byResult }
}
export async function getAllLogs(params = {}) {
  const res = await api.get('/audit', { params });
  return res.data.data;
}
export async function getAllStats(params = {}) {
  const res = await api.get('/audit/stats', { params });
  return res.data.data;
}