// Single source of truth for comparing permission strength, used both to
// enforce "can this user DOWNLOAD this file" and to cap what an owner is
// allowed to grant on a HIGH/CRITICAL file (Phase 11's maxSharePermission).
export const PERMISSION_ORDER = { VIEW: 0, DOWNLOAD: 1, EDIT: 2, OWNER: 3 };

export function permissionAtLeast(have, need) {
  return (PERMISSION_ORDER[have] ?? -1) >= (PERMISSION_ORDER[need] ?? Infinity);
}