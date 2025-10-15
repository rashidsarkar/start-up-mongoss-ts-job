import jwt, { JwtPayload, Secret } from 'jsonwebtoken';

export const generateToken = (payload: any, secret: string, expireIn: any) => {
  const token = jwt.sign(payload, secret, {
    algorithm: 'HS256',
    expiresIn: expireIn,
  });
  return token;
};

export const verifyToken = (token: string, secret: Secret) => {
  return jwt.verify(token, secret) as JwtPayload;
};
