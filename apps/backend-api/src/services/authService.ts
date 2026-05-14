import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { generateTokens } from '../utils/tokenUtils'; // Create this util

const prisma = new PrismaClient();

interface ServiceResult<T> {
  success: boolean;
  message: string;
  data?: T;
}

export const loginService = async (
  email: string,
  password: string
): Promise<ServiceResult<AuthResponse>> => {
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user || !await bcrypt.compare(password, user.hashedPassword)) {
    return { success: false, message: 'Invalid email or password' };
  }

  const tokens = generateTokens(user.id);
  const { hashedPassword, ...userWithoutPassword } = user; // Omit sensitive data

  return {
    success: true,
    message: 'Login successful',
    data: {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: userWithoutPassword as Omit<User, 'hashedPassword'>
    }
  };
};

export const registerService = async (
  email: string,
  password: string,
  name?: string
): Promise<ServiceResult<AuthResponse>> => {
  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) {
    return { success: false, message: 'Email already registered' };
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: {
      email,
      name,
      hashedPassword,
    },
  });

  const tokens = generateTokens(user.id);
  const { hashedPassword: _, ...userWithoutPassword } = user; // Omit password from response

  return {
    success: true,
    message: 'Registration successful',
    data: {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: userWithoutPassword as Omit<User, 'hashedPassword'>
    }
  };
};