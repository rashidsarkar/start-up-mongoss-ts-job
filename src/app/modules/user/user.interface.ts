/* eslint-disable no-unused-vars */
import { Model } from 'mongoose';
import { USER_ROLE } from './user.const';
export type TUserRole = keyof typeof USER_ROLE;
export type TUser = {
  name: string;
  email: string;
  password: string;
  role: TUserRole;
  isBlocked: boolean;
};
export type TLoginUser = {
  email: string;
  password: string;
};

export interface UserModel extends Model<TUser> {
  // is user exists by email
  isUserExists(email: string): Promise<boolean>;
  isPasswordMatch(plainTextPass: string, hashedPass: string): Promise<boolean>;
}
