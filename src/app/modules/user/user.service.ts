import { StatusCodes } from 'http-status-codes';
import AppError from '../../errors/AppError';
import { TUser } from './user.interface';
import { User } from './user.model';

const createUserIntoDB = async (userData: TUser) => {
  const existingUser = await User.isUserExists(userData.email);

  if (existingUser) {
    throw new AppError(StatusCodes.CONFLICT, 'Email is already in use');
  }
  await User.create(userData);
  const result = await User.findOne({ email: userData.email }).select(
    '_id name email',
  );

  return result;
};

const getUserFromDb = async () => {
  const user = await User.find().select('_id name email role');
  if (!user) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User not found');
  }
  return user;
};

export const UserServices = {
  createUserIntoDB,

  getUserFromDb,
};
