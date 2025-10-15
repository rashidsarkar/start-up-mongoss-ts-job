import { StatusCodes } from 'http-status-codes';
import AppError from '../../errors/AppError';
import { TLoginUser } from '../user/user.interface';
import { User } from '../user/user.model';

import config from '../../config';
import { generateToken, verifyToken } from '../../utils/generateToken';

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
const refreshToken = async (token: string) => {
  let decodedData;
  try {
    decodedData = verifyToken(token, config.jwt_refresh_secret as string);
  } catch (error) {
    console.log(error);
    throw new AppError(StatusCodes.FORBIDDEN, 'You are not Authorized ');
  }
  const isUserExists = await User.isUserExists(decodedData?.email);
  if (!isUserExists) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User not found');
  }

  const jwtPayload = {
    email: decodedData?.email,
    role: decodedData?.role,
  };
  const accessToken = generateToken(
    jwtPayload,
    config.jwt_access_secret as string,
    config.jwt_access_expires_in,
  );

  return { accessToken };
};

const getMe = async (reqEmail: string, tokenEmail: string) => {
  if (reqEmail !== tokenEmail) {
    throw new AppError(StatusCodes.FORBIDDEN, 'You are not Authorized ');
  }
  const user = await User.findOne({ email: reqEmail }).select(
    '_id name email role',
  );
  if (!user) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User not found');
  }
  return user;
};
export const AuthServices = {
  loginUser,
  refreshToken,
  getMe,
};
