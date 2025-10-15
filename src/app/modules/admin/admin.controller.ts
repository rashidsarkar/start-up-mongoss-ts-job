/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-unused-vars */
import { Request, Response } from 'express';
import catchAsync from '../../utils/catchAsync';
import { AdminServices } from './admin.service';
import { StatusCodes } from 'http-status-codes';

const blockUser = catchAsync(async (req: Request, res: Response) => {
  const requester = req.tokenUser;

  const { userId } = req.params;
  const result = await AdminServices.blockUSerFromDb(userId, requester);

  res.status(StatusCodes.OK).json({
    success: true,
    message: 'User blocked successfully',
    statusCode: StatusCodes.OK,
  });
});

export const AdminControllers = {
  blockUser,
};
