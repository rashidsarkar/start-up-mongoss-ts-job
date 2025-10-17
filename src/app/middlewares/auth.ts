import { NextFunction, Request, Response } from 'express';

import catchAsync from '../utils/catchAsync';
import AppError from '../errors/AppError';
import { StatusCodes } from 'http-status-codes';
import jwt, { JwtPayload } from 'jsonwebtoken';
import config from '../config';
import { TUserRole } from '../modules/user/user.interface';
import { User } from '../modules/user/user.model';

const auth = (...requiredRoles: TUserRole[]) => {
  return catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const tokenHeader = req.headers.authorization;

    // if the token is not provided, return an error
    if (!tokenHeader) {
      throw new AppError(
        StatusCodes.UNAUTHORIZED,
        'You are not logged in! Please login to get access',
      );
    }

    // check if token is valid
    const token = tokenHeader;

    const decoded = jwt.verify(
      token,
      config.jwt_access_secret as string,
    ) as JwtPayload;
    // console.log(decoded);
    if (!decoded) {
      throw new AppError(StatusCodes.UNAUTHORIZED, 'Invalid token');
    }
    const { role, email, iat } = decoded;

    const existingUser = await User.findOne({ email: email });
    if (!existingUser) {
      throw new AppError(StatusCodes.NOT_FOUND, 'User not found');
    }
    const isBlocked = existingUser.isBlocked;
    if (isBlocked) {
      throw new AppError(StatusCodes.FORBIDDEN, 'User is Blocked');
    }
    // console.log(requiredRoles);

    if (existingUser.passwordChangedAt) {
      const passwordChangedTimestamp = parseInt(
        (existingUser.passwordChangedAt.getTime() / 1000).toString(),
      );
      if (iat && iat < passwordChangedTimestamp) {
        throw new AppError(
          StatusCodes.UNAUTHORIZED,
          'Password recently changed. Please log in again.',
        );
      }
    }

    if (requiredRoles && !requiredRoles.includes(role)) {
      throw new AppError(
        StatusCodes.FORBIDDEN,
        'You do not have permission to access this resource',
      );
    }

    req.tokenUser = decoded as JwtPayload;
    next();
  });
};

export default auth;
