import { Router } from 'express';
import { body } from 'express-validator';
import { getHealth, validationDemo } from '../controllers/health.controller.js';
import { validate } from '../middleware/validate.js';

const router = Router();

router.get('/', getHealth);

// TEMPORARY: exists only to prove the validation pipeline works.
// It is deleted in Phase 5 when real register/login routes replace it.
router.post(
  '/validation-demo',
  [
    body('name')
      .isString().withMessage('name must be text').bail()
      .trim()
      .isLength({ min: 2, max: 100 }).withMessage('name must be 2 to 100 characters'),
    body('email')
      .isString().withMessage('email must be text').bail()
      .trim()
      .isEmail().withMessage('email is not valid').bail()
      .toLowerCase(),
  ],
  validate,
  validationDemo
);

export default router;