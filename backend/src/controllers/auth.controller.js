import * as authService from '../services/auth.service.js';
import { sendSuccess } from '../utils/apiResponse.js';

// SECURITY: fields are picked out of req.body one by one, never spread.
// A client that sends { "role": "ADMIN" } gets nothing (no mass-assignment).

export async function register(req, res) {
  const { name, email, password } = req.body;
  const user = await authService.registerUser({ name, email, password }, { ipAddress: req.ip });
  return sendSuccess(res, { user }, 'Registration successful', 201);
}

export async function login(req, res) {
  const { email, password } = req.body;
  const result = await authService.loginUser({ email, password }, { ipAddress: req.ip });
  return sendSuccess(res, result, 'Login successful');
}

export async function me(req, res) {
  return sendSuccess(res, { user: authService.toPublicUser(req.user) });
}

export async function logout(req, res) {
  await authService.logoutUser({ user: req.user, auth: req.auth }, { ipAddress: req.ip });
  return sendSuccess(res, null, 'Logged out');
}