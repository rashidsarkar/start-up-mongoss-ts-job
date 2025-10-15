import express from 'express';
import { UserControllers } from './user.controller';
import validateRequest from '../../middlewares/validateRequest';
import { UserValidation } from './user.validation';
import auth from '../../middlewares/auth';
import { USER_ROLE } from './user.const';

const router = express.Router();
router.post(
  '/register',
  validateRequest(UserValidation.registerUserValidationSchema),
  UserControllers.createUser,
);

//TODO -  removed this code after test
router.get('/getAllUser', auth(USER_ROLE.user), UserControllers.getUsers);
export const UserRoutes = router;
// todo
