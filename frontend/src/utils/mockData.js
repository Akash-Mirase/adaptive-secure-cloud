// TEMPORARY placeholder data for Phase 2 UI work.
// It is replaced by real API calls in later phases. None of it is real.
export const mockFiles = [
  { id: 1, name: 'passport.pdf', size: 1_250_000, type: 'application/pdf', riskScore: 9, riskLevel: 'CRITICAL', createdAt: '2026-09-20T10:15:00Z' },
  { id: 2, name: 'salary-slip.pdf', size: 480_000, type: 'application/pdf', riskScore: 7, riskLevel: 'HIGH', createdAt: '2026-09-21T09:00:00Z' },
  { id: 3, name: 'project-report.docx', size: 2_400_000, type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', riskScore: 5, riskLevel: 'MEDIUM', createdAt: '2026-09-22T14:30:00Z' },
  { id: 4, name: 'holiday.jpg', size: 3_800_000, type: 'image/jpeg', riskScore: 1, riskLevel: 'LOW', createdAt: '2026-09-25T18:45:00Z' },
];

export const mockSharedFiles = [
  { id: 11, name: 'team-notes.pdf', owner: 'alice@example.com', permission: 'DOWNLOAD', riskLevel: 'MEDIUM', sharedAt: '2026-09-23T11:00:00Z' },
  { id: 12, name: 'design.png', owner: 'bob@example.com', permission: 'VIEW', riskLevel: 'LOW', sharedAt: '2026-09-24T16:20:00Z' },
];

export const mockAuditLogs = [
  { id: 1, eventType: 'LOGIN', fileName: null, result: 'SUCCESS', ip: '127.0.0.1', at: '2026-09-28T08:00:00Z' },
  { id: 2, eventType: 'UPLOAD', fileName: 'passport.pdf', result: 'SUCCESS', ip: '127.0.0.1', at: '2026-09-28T08:05:00Z' },
  { id: 3, eventType: 'RISK_CLASSIFICATION', fileName: 'passport.pdf', result: 'SUCCESS', ip: '127.0.0.1', at: '2026-09-28T08:05:01Z' },
  { id: 4, eventType: 'ACCESS_DENIED', fileName: 'salary-slip.pdf', result: 'DENIED', ip: '10.0.0.7', at: '2026-09-28T08:40:00Z' },
  { id: 5, eventType: 'LOGIN_FAILED', fileName: null, result: 'FAILURE', ip: '10.0.0.7', at: '2026-09-28T08:41:00Z' },
];