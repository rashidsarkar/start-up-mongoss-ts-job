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

export const AuthControllers = {
  loginUser,
  refreshToken,
  getMe,
};
