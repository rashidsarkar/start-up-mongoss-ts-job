import { StatusCodes } from 'http-status-codes';
import catchAsync from '../../utils/catchAsync';
import sendResponse from '../../utils/sendResponse';
import { AuthServices } from './auth.service';

const loginUser = catchAsync(async (req, res) => {
  const result = await AuthServices.loginUser(req.body);
  const { refreshToken, accessToken } = result;
  res.cookie('refreshToken', refreshToken, {
    secure: true,
    httpOnly: true,
  });
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Login successful',
    data: { accessToken },
  });
});

const refreshToken = catchAsync(async (req, res) => {
  const { refreshToken } = req.cookies;
  const result = await AuthServices.refreshToken(refreshToken);

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'New access token generated successfully',
    data: result,
  });
});
const getMe = catchAsync(async (req, res) => {
  const result = await AuthServices.getMe(
    req.query.email as string,
    req.tokenUser?.email as string,
  );

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'User found',
    data: result,
  });
});

const changePassword = catchAsync(async (req, res) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const user: any = req.tokenUser;
  const payload = req.body;
  const result = await AuthServices.changePassword(user, payload);
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Password changed successfully',
    data: result,
  });
});

const forgotPassword = catchAsync(async (req, res) => {
  const { email } = req.body;
  // eslint-disable-next-line no-unused-vars, @typescript-eslint/no-unused-vars
  const result = await AuthServices.forgotPassword(email);
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Password reset URL sent to email successfully',
    data: 'check your email inbox',
  });
});
const resetPassword = catchAsync(async (req, res) => {
  const { email, newPassword } = req.body;
  const token = req.headers.authorization;

  const result = await AuthServices.resetPassword(
    email,
    newPassword,
    token as string,
  );
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Password reset successfully',
    data: result,
  });
});

export const AuthControllers = {
  loginUser,
  refreshToken,
  getMe,
  changePassword,
  forgotPassword,
  resetPassword,
};
