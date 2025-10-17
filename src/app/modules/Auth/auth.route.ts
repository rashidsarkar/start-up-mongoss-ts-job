import express from 'express';
import validateRequest from '../../middlewares/validateRequest';
import { AuthValidation } from './auth.validation';
import { AuthControllers } from './auth.controller';
import auth from '../../middlewares/auth';
import { USER_ROLE } from '../user/user.const';

const router = express.Router();

router.post(
  '/login',
  validateRequest(AuthValidation.loginValidationSchema),
  AuthControllers.loginUser,
);
router.post('/refresh-token', AuthControllers.refreshToken);
router.post(
  '/change-password',
  auth(USER_ROLE.admin, USER_ROLE.user),
  validateRequest(AuthValidation.passwordChangeValidationSchema),
  AuthControllers.changePassword,
);
router.post(
  '/forgot-password',
  validateRequest(AuthValidation.forgotPasswordValidationSchema),

  AuthControllers.forgotPassword,
);

router.post(
  '/reset-password',
  validateRequest(AuthValidation.resetPasswordValidationSchema),
  AuthControllers.resetPassword,
);

router.get('/me', auth(USER_ROLE.admin, USER_ROLE.user), AuthControllers.getMe);

export const AuthRoutes = router;
