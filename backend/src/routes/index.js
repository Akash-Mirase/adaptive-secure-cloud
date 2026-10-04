import { Router } from 'express';
import healthRoutes from './health.routes.js';
import authRoutes from './auth.routes.js';
import filesRoutes from './files.routes.js';
import usersRoutes from './users.routes.js';

// Every feature router is mounted here so app.js never changes again.
const router = Router();

router.use('/health', healthRoutes);
router.use('/auth', authRoutes);
router.use('/files', filesRoutes);
router.use('/users', usersRoutes);
// Later: /files (Phase 6), /shares (Phase 12), /audit (Phase 13)

export default router;