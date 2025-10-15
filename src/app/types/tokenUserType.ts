import { JwtPayload } from 'jsonwebtoken';

export type TJwtUserPayload = JwtPayload & { email: string; role: string };
