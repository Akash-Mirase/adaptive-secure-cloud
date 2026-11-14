import { Router } from 'express';
import healthRoutes from './health.routes.js';
import authRoutes from './auth.routes.js';
import filesRoutes from './files.routes.js';
import usersRoutes from './users.routes.js';
import auditRoutes from './audit.routes.js';
import mfaRoutes from './mfa.routes.js';
import alertsRoutes from './alerts.routes.js'; 



// Every feature router is mounted here so app.js never changes again.
const router = Router();

router.use('/health', healthRoutes);
router.use('/auth', authRoutes);
router.use('/files', filesRoutes);
router.use('/users', usersRoutes);

router.use('/audit', auditRoutes);
router.use('/mfa', mfaRoutes);
router.use('/alerts', alertsRoutes);

export default router;