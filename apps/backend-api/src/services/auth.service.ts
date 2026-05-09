import { AuthRepository } from '../repositories/auth.repository';
import { PasswordUtil } from '../utils/password.util';
import { JwtUtil } from '../utils/jwt.util';
import { AppError } from '../utils/AppError';
import { RegisterDto, LoginDto, AuthResponse, UserResponse } from '../types/auth.types';
import { User } from '@prisma/client';

export class AuthService {
  private authRepository: AuthRepository;

  constructor() {
    this.authRepository = new AuthRepository();
  }

  /**
   * Helper method to strip sensitive data (like passwords) from the raw database record.
   * This guarantees that passwords never leak to the Controller layer.
   */
  private sanitizeUser(user: User): UserResponse {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt,
    };
  }

  /**
   * Executes the business logic for registering a new user.
   */
  public async register(data: RegisterDto): Promise<AuthResponse> {
    // 1. Business Rule: Emails must be unique
    const existingUser = await this.authRepository.findUserByEmail(data.email);
    if (existingUser) {
      throw new AppError(409, 'User with this email already exists');
    }

    // 2. Security: Hash the password BEFORE it touches the database layer
    const hashedPassword = await PasswordUtil.hashPassword(data.password);

    // 3. Data Storage: Delegate the actual insertion to the Repository
    const newUser = await this.authRepository.createUser({
      email: data.email,
      password: hashedPassword,
      name: data.name,
    });

    // 4. Authentication: Generate access token for immediate login upon registration
    const accessToken = JwtUtil.generateAccessToken({ userId: newUser.id });
    
    // 5. Response Formatting: Ensure exact alignment with AuthResponse type
    return {
      user: this.sanitizeUser(newUser),
      tokens: { accessToken },
    };
  }

  /**
   * Executes the business logic for logging in an existing user.
   */
  public async login(data: LoginDto): Promise<AuthResponse> {
    // 1. Fetch user (which includes the hashed password) from Repository
    const user = await this.authRepository.findUserByEmail(data.email);
    if (!user) {
      // Security: We intentionally use a vague error message to prevent "email enumeration"
      throw new AppError(401, 'Invalid email or password');
    }

    // 2. Security: Safely compare the plain text attempt with the stored hash
    const isPasswordValid = await PasswordUtil.comparePassword(data.password, user.password);
    if (!isPasswordValid) {
      throw new AppError(401, 'Invalid email or password');
    }

    // 3. Authentication: Generate access token
    const accessToken = JwtUtil.generateAccessToken({ userId: user.id });

    // 4. Response Formatting: Strip the password and return standardized auth object
    return {
      user: this.sanitizeUser(user),
      tokens: { accessToken },
    };
  }
}
