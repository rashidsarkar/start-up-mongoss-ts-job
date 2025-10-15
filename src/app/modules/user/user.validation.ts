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
    password: z.string().min(6, 'Password must be at least 6 characters long'),
  }),
});

export const UserValidation = {
  registerUserValidationSchema,
};
