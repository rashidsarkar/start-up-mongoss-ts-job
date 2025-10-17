import { StatusCodes } from 'http-status-codes';
import AppError from '../../errors/AppError';
import { TLoginUser } from '../user/user.interface';
import { User } from '../user/user.model';
import bcrypt from 'bcrypt';

import config from '../../config';
import { generateToken, verifyToken } from '../../utils/generateToken';
import { emailSender } from '../../utils/emailSender';

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
    '_id name email role isBlocked',
  );
  if (!user) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User not found');
  }
  return user;
};

const changePassword = async (
  tokenUser: { email: string },
  payload: {
    oldPassword: string;
    newPassword: string;
  },
) => {
  // 1. Find user by email
  const user = await User.findOne({ email: tokenUser.email });
  if (!user) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User not found');
  }

  // 2. Check old password
  const isPassMatch = await User.isPasswordMatch(
    payload.oldPassword,
    user.password,
  );
  if (!isPassMatch) {
    throw new AppError(StatusCodes.FORBIDDEN, 'Old password is incorrect');
  }

  // 3. Hash new password
  const newHashedPassword = await bcrypt.hash(
    payload.newPassword,
    Number(config.bcrypt_salt),
  );

  // 4. Update user password
  await User.updateOne(
    { email: tokenUser.email },
    { password: newHashedPassword, passwordChangedAt: new Date() },
  );

  // 5. Return success message
  return {
    message: 'Password changed successfully',
  };
};
// eslint-disable-next-line @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any
const forgotPassword = async (email: string) => {
  const userData = await User.findOne({
    email: email,
  });
  if (!userData) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User not found');
  }

  const jwtPayload = {
    email: userData.email,
    role: userData.role,
  };
  const resetPassToken = generateToken(
    jwtPayload,
    config.jwt_reset_password_secret as string,
    config.jwt_reset_password_expires_in,
  );

  const resetPassLink = `${config.jwt_reset_password_link}?email=${email}&token=${resetPassToken}`;
  console.log(resetPassLink);

  await emailSender(
    email,
    `
    <h2>Please click on the given link to reset your password</h2>
    <a href=${resetPassLink} target="_blank">${resetPassLink}</a>
    <p>Note: This link is valid for 10 minutes only.</p>
    `,
  );
  return { resetPassToken };
};

const resetPassword = async (
  email: string,
  newPassword: string,
  token: string,
) => {
  const decodedData = verifyToken(
    token,
    config.jwt_reset_password_secret as string,
  );
  if (decodedData?.email !== email) {
    throw new AppError(StatusCodes.FORBIDDEN, 'You are not Authorized ');
  }
  const user = await User.findOne({ email: email, isBlocked: false });
  if (!user) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User not found');
  }
  const newHashedPassword = await bcrypt.hash(
    newPassword,
    Number(config.bcrypt_salt),
  );
  await User.findOneAndUpdate(
    { email: email },
    {
      password: newHashedPassword,
      passwordChangedAt: new Date(),
    },
  );
  return 'Password reset successfully';
};

export const AuthServices = {
  loginUser,
  refreshToken,
  getMe,
  changePassword,
  forgotPassword,
  resetPassword,
};
