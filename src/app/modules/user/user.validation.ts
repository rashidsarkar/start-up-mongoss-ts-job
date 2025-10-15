import { z } from 'zod';

const registerUserValidationSchema = z.object({
  body: z.object({
    name: z
      .string()
      .trim()
      .min(1, 'Name is required')
      .refine((value) => /^[A-Z]/.test(value), {
        message: 'First Name must start with a capital letter',
      }),
    email: z.string().email('Invalid email format').min(1, 'Email is required'),
    password: z.string().min(1, 'Password is required'),
  }),
});
const loginValidationSchema = z.object({
  body: z.object({
    email: z.string({
      required_error: 'email is required',
    }),
    password: z.string({
      required_error: 'password is required',
    }),
  }),
});

export const UserValidation = {
  registerUserValidationSchema,
  loginValidationSchema,
};
