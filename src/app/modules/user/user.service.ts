import { StatusCodes } from 'http-status-codes';
import AppError from '../../errors/AppError';
import { TLoginUser, TUser } from './user.interface';
import { User } from './user.model';
import jwt from 'jsonwebtoken';
import config from '../../config';

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

const loginUser = async (userData: TLoginUser) => {
  const existingUser = await User.findOne({ email: userData.email });
  if (!existingUser) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User not found');
  }
  // const isDeleted = existingUser.isBlocked;
  // if (isDeleted) {
  //   throw new AppError(StatusCodes.FORBIDDEN, 'User is Blocked');
  // }
  // const isMatchPass = await User.isPasswordMatch(
  //   userData.password,
  //   existingUser.password,
  // );
  // if (!isMatchPass) {
  //   throw new AppError(StatusCodes.FORBIDDEN, 'Invalid password');
  // }

  const jwtPayload = {
    email: existingUser.email,
    role: existingUser.role,
  };
  const accessToken = jwt.sign(jwtPayload, config.jwt_access_secret as string, {
    expiresIn: '10d',
  });
  return {
    token: accessToken,
  };
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
  loginUser,
  getUserFromDb,
};
