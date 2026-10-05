import * as authService from '../services/auth.service.js';
import { sendSuccess } from '../utils/apiResponse.js';

// SECURITY: fields are picked out of req.body one by one, never spread.
// A client that sends { "role": "ADMIN" } gets nothing (no mass-assignment).

export async function register(req, res) {
  const { name, email, password } = req.body;
  const keyBundle = {
    kdfIterations: req.body.kdfIterations,
    kdfSalt: req.body.kdfSalt,
    wrappedMasterKey: req.body.wrappedMasterKey,
    masterKeyIv: req.body.masterKeyIv,
    recoveryWrappedMasterKey: req.body.recoveryWrappedMasterKey,
    recoveryIv: req.body.recoveryIv,
    recoveryKey: req.body.recoveryKey,
    publicKey: req.body.publicKey,
    wrappedPrivateKey: req.body.wrappedPrivateKey,
    privateKeyIv: req.body.privateKeyIv,
  };
  const user = await authService.registerUser({ name, email, password, keyBundle }, { ipAddress: req.ip });
  return sendSuccess(res, { user }, 'Registration successful', 201);
}

export async function getKeys(req, res) {
  const keys = await authService.getKeyBundleForUser(req.user.id);
  return sendSuccess(res, { keys });
}

export async function getRecoveryBundle(req, res) {
  const bundle = await authService.getRecoveryBundle(req.query.email);
  return sendSuccess(res, bundle);
}

export async function recover(req, res) {
  const { email, recoveryKey, newPassword } = req.body;
  const keyBundle = {
    kdfIterations: req.body.kdfIterations,
    kdfSalt: req.body.kdfSalt,
    wrappedMasterKey: req.body.wrappedMasterKey,
    masterKeyIv: req.body.masterKeyIv,
  };
  await authService.recoverAccount({ email, recoveryKey, newPassword, keyBundle }, { ipAddress: req.ip });
  return sendSuccess(res, null, 'Account recovered. You can now sign in with your new password.');
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

export async function stepUp(req, res) {
  const { password } = req.body;
  const result = await authService.stepUpVerify({ userId: req.user.id, password }, { ipAddress: req.ip });
  return sendSuccess(res, result, 'Step-up verification successful');
}

export async function regenerateRecoveryKey(req, res) {
  const { recoveryWrappedMasterKey, recoveryIv, recoveryKey } = req.body;
  await authService.regenerateRecoveryKey(
    { userId: req.user.id, recoveryWrappedMasterKey, recoveryIv, recoveryKey },
    { ipAddress: req.ip }
  );
  return sendSuccess(res, null, 'Recovery key regenerated');
}