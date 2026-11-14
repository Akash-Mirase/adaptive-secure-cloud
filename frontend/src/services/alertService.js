import api from './api.js';

export async function getMyAlerts(params = {}) {
  return (await api.get('/alerts/me', { params })).data.data; // { alerts, total }
}
export async function getAllAlerts(params = {}) {
  return (await api.get('/alerts', { params })).data.data;
}