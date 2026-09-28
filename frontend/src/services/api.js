import axios from 'axios';

// One shared Axios instance; Phase 5 will attach the JWT here.
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000/api',
  timeout: 15000,
});

export default api;