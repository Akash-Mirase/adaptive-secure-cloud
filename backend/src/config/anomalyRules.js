// All thresholds live here. Every restriction is temporary by design (expiresMinutes).
export const ANOMALY_RULES = [
  { rule: 'FAILED_LOGINS', eventType: 'LOGIN_FAILED', result: 'FAILURE', windowMinutes: 10, threshold: 5,
    severity: 'MEDIUM', restriction: 'NONE', expiresMinutes: 0,
    describe: (n, w) => `${n} failed login attempts in ${w} minutes` },
  { rule: 'REPEATED_DENIALS', eventType: 'ACCESS_DENIED', result: 'DENIED', windowMinutes: 10, threshold: 5,
    severity: 'HIGH', restriction: 'REQUIRE_STEP_UP', expiresMinutes: 30,
    describe: (n, w) => `${n} unauthorized access attempts in ${w} minutes` },
  { rule: 'BULK_DOWNLOADS', eventType: 'DOWNLOAD', result: 'SUCCESS', windowMinutes: 10, threshold: 20,
    severity: 'HIGH', restriction: 'THROTTLE_DOWNLOADS', expiresMinutes: 15,
    describe: (n, w) => `${n} downloads in ${w} minutes (unusually high)` },
  { rule: 'SHARING_BURST', eventType: 'SHARE', result: 'SUCCESS', windowMinutes: 10, threshold: 10,
    severity: 'MEDIUM', restriction: 'REQUIRE_STEP_UP', expiresMinutes: 30,
    describe: (n, w) => `${n} files shared in ${w} minutes (abnormal sharing)` },
];