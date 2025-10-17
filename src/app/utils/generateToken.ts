/* eslint-disable @typescript-eslint/no-explicit-any */
import jwt, { JwtPayload, Secret } from 'jsonwebtoken';
import AppError from '../errors/AppError';

export const generateToken = (payload: any, secret: string, expireIn: any) => {
  const token = jwt.sign(payload, secret, {
    algorithm: 'HS256',
    expiresIn: expireIn,
  });
  return token;
};

export const verifyToken = (token: string, secret: Secret) => {
  try {
    return jwt.verify(token, secret) as JwtPayload;
  } catch (error) {
    console.log(error);
    throw new AppError(401, 'Invalid or expired token');
  }
};
