import { StatusCodes } from 'http-status-codes';
import AppError from '../../errors/AppError';
import { TLoginUser } from '../user/user.interface';
import { User } from '../user/user.model';
import jwt from 'jsonwebtoken';
import config from '../../config';
import { generateToken } from '../../utils/generateToken';

const loginUser = async (userData: TLoginUser) => {
  const existingUser = await User.findOne({ email: userData.email });
  if (!existingUser) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User not found');
  }
  const isDeleted = existingUser.isBlocked;
  if (isDeleted) {
    throw new AppError(StatusCodes.FORBIDDEN, 'User is Blocked');
  }
  const isMatchPass = await User.isPasswordMatch(
    userData.password,
    existingUser.password,
  );
  if (!isMatchPass) {
    throw new AppError(StatusCodes.FORBIDDEN, 'Invalid password');
  }

  const jwtPayload = {
    email: existingUser.email,
    role: existingUser.role,
  };

  const accessToken = generateToken(
    jwtPayload,
    config.jwt_access_secret as string,
    config.jwt_access_expires_in,
  );

  const refreshToken = generateToken(
    jwtPayload,
    config.jwt_refresh_secret as string,
    config.jwt_refresh_expires_in,
  );

  return { accessToken, refreshToken };
};

export const AuthServices = {
  loginUser,
};
