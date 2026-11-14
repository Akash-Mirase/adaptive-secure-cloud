import { sendSuccess } from '../utils/apiResponse.js';
import * as alerts from '../models/securityAlert.model.js';

export const mine = async (req, res) =>
  sendSuccess(res, await alerts.list({ userId: req.user.id, page: req.query.page, pageSize: req.query.pageSize }));
export const all = async (req, res) =>
  sendSuccess(res, await alerts.list({ page: req.query.page, pageSize: req.query.pageSize }));