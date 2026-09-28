import { Router } from 'express';
import healthRoutes from './health.routes.js';

// Every feature router is mounted here so app.js never changes again.
const router = Router();

router.use('/health', healthRoutes);
// Later: /auth (Phase 5), /files (Phase 6), /shares (Phase 12), /audit (Phase 13)

export default router;