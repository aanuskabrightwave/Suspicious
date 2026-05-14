import { Request, Response } from 'express';
import { AuthService } from '../services/auth.service';
import { catchAsync } from '../utils/catchAsync';
import { RegisterDto, LoginDto } from '../types/auth.types';
import { AuthUser } from '../types/auth.types';

// Extend Express Request to include the authenticated user attached by auth middleware
export interface AuthenticatedRequest extends Request {
  user?: AuthUser;
}

export class AuthController {
  private authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }

  /**
   * POST /api/v1/auth/register
   * Handles new user registration requests.
   * Extracts body, delegates to Service, returns standardized 201 response.
   */
  public register = catchAsync(async (req: Request, res: Response) => {
    const data: RegisterDto = req.body;

    // Delegate all registration business logic to the Service layer
    const result = await this.authService.register(data);

    res.status(201).json({
      success: true,
      message: 'Registration successful',
      data: result,
    });
  });

  /**
   * POST /api/v1/auth/login
   * Handles user login requests.
   * Extracts credentials, delegates to Service, returns standardized 200 response.
   */
  public login = catchAsync(async (req: Request, res: Response) => {
    const data: LoginDto = req.body;

    // Delegate all login and token generation logic to the Service layer
    const result = await this.authService.login(data);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: result,
    });
  });

  /**
   * GET /api/v1/auth/profile
   * Returns the currently authenticated user's profile.
   * req.user is attached by the Auth Middleware BEFORE this controller runs.
   */
  public getProfile = catchAsync(async (req: AuthenticatedRequest, res: Response) => {
    // The Auth Middleware verifies the JWT and attaches the user, so we can safely use it here
    res.status(200).json({
      success: true,
      message: 'Profile fetched successfully',
      data: req.user,
    });
  });

  /**
   * POST /api/v1/auth/logout
   * Handles logout structure.
   * With stateless JWTs, logout is primarily handled on the client (discard token).
   * This endpoint exists as a proper RESTful contract and a hook for future
   * refresh token invalidation (e.g., clearing a Redis session or a DB blacklist).
   */
  public logout = catchAsync(async (req: AuthenticatedRequest, res: Response) => {
    // SCALABILITY: Future refresh token invalidation logic goes here
    // e.g., await this.authService.invalidateRefreshToken(req.user?.id);

    res.status(200).json({
      success: true,
      message: 'Logout successful',
    });
  });
}
