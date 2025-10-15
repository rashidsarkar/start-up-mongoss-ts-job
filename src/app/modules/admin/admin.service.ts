import { JwtPayload } from 'jsonwebtoken';
import { User } from '../user/user.model';
import { USER_ROLE } from '../user/user.const';
import AppError from '../../errors/AppError';
import { StatusCodes } from 'http-status-codes';

const blockUSerFromDb = async (id: string, requester: JwtPayload) => {
  //   console.log(requester);
  //   console.log(id);
  const user = await User.findById(id);
  //   console.log(user);
  if (!user) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User not found');
  }
  if (user.isBlocked) {
    throw new AppError(StatusCodes.FORBIDDEN, 'User Already blocked');
  }
  if (requester.role !== USER_ROLE.admin) {
    throw new AppError(StatusCodes.FORBIDDEN, 'Only admins can block users');
  }

  const blockUser = await User.findByIdAndUpdate(id, { isBlocked: true });

  return blockUser;
};

export const AdminServices = {
  blockUSerFromDb,
};
