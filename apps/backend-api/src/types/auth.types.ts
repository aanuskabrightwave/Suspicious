// 1. Data Transfer Objects (DTOs)
// These define the exact expected shape of incoming HTTP request bodies.
export interface RegisterDto {
  email: string;
  password: string;
  name?: string;
}

export interface LoginDto {
  email: string;
  password: string;
}

// 2. JWT and Middleware Types
// Defines exactly what data is embedded inside the JSON Web Token.
export interface TokenPayload {
  userId: string;
}

// Defines the strictly-typed user object that our Auth Middleware 
// will attach to the Express Request object (e.g., req.user).
export interface AuthUser {
  id: string;
  email: string;
  name: string | null;
  createdAt: Date;
}

// 3. Response Structures
// Defines the strictly sanitized user profile returned to the frontend.
// CRITICAL: Notice that the 'password' field is deliberately omitted.
export interface UserResponse {
  id: string;
  email: string;
  name: string | null;
  createdAt: Date;
}

// Defines the token structure returned after successful authentication.
export interface TokenResponse {
  accessToken: string;
  // SCALABILITY: refreshToken?: string; 
}

// The unified, standardized response body sent back to the client 
// upon successful login or registration.
export interface AuthResponse {
  user: UserResponse;
  tokens: TokenResponse;
}
