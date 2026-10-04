import { sendSuccess } from '../utils/apiResponse.js';
import * as auditService from '../services/audit.service.js';

function filtersFromQuery(q, { forceUserId } = {}) {
  return {
    userId: forceUserId ?? (q.userId ? Number(q.userId) : undefined),
    eventType: q.eventType || undefined,
    result: q.result || undefined,
    fileId: q.fileId || undefined,
    dateFrom: q.dateFrom || undefined,
    dateTo: q.dateTo || undefined,
  };
}
function paginationFromQuery(q) {
  return { page: Number(q.page) || 1, pageSize: Number(q.pageSize) || 25 };
}

// Any authenticated user: their OWN activity only. userId is forced, not
// read from the query string, so nobody can pass ?userId=someoneElse to see
// another person's activity through this route.
export async function listMine(req, res) {
  const filters = filtersFromQuery(req.query, { forceUserId: req.user.id });
  const pagination = paginationFromQuery(req.query);
  const { logs, total } = await auditService.queryAuditLogs(filters, pagination);
  return sendSuccess(res, { logs, total, ...pagination });
}

export async function myStats(req, res) {
  const stats = await auditService.getSecurityStats({ userId: req.user.id });
  return sendSuccess(res, stats);
}

// ADMIN only (enforced by requireRole in the route): every user's activity,
// optionally filtered to one user/file/type/result/date range.
export async function listAll(req, res) {
  const filters = filtersFromQuery(req.query);
  const pagination = paginationFromQuery(req.query);
  const { logs, total } = await auditService.queryAuditLogs(filters, pagination);
  return sendSuccess(res, { logs, total, ...pagination });
}

export async function allStats(req, res) {
  const filters = filtersFromQuery(req.query);
  const stats = await auditService.getSecurityStats(filters);
  return sendSuccess(res, stats);
}