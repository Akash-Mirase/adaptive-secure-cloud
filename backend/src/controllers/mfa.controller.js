import { sendSuccess } from '../utils/apiResponse.js';
import * as mfaService from '../services/mfa.service.js';

export const status = async (req, res) => sendSuccess(res, await mfaService.getStatus(req.user.id));
export const enroll = async (req, res) =>
  sendSuccess(res, await mfaService.beginEnrollment(req.user, req.body.password, { ipAddress: req.ip }));
export const confirm = async (req, res) =>
  sendSuccess(res, await mfaService.confirmEnrollment(req.user.id, req.body.code, { ipAddress: req.ip }), 'MFA enabled', 201);
export async function disable(req, res) {
  const { password, code, recoveryCode } = req.body;
  await mfaService.disable(req.user.id, { password, code, recoveryCode }, { ipAddress: req.ip });
  return sendSuccess(res, null, 'MFA disabled');
}
export const regenerate = async (req, res) =>
  sendSuccess(res, await mfaService.regenerateRecoveryCodes(req.user.id, { password: req.body.password, code: req.body.code }, { ipAddress: req.ip }));