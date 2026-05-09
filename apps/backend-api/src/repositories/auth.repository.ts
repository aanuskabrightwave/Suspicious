import { prisma } from '../config/database';
import { User, Prisma } from '@prisma/client';

export class AuthRepository {
  /**
   * Finds a user strictly by their email address.
   * Used during Login (to fetch the password hash) and Registration (to check for duplicates).
   * 
   * @param email - The email address to query
   * @returns The complete User record from the database, or null if not found
   */
  public async findUserByEmail(email: string): Promise<User | null> {
    return prisma.user.findUnique({
      where: { email },
    });
  }

  /**
   * Finds a user strictly by their unique ID.
   * Used heavily by the Auth Middleware to verify a user still exists in the DB 
   * after their JWT has been decoded.
   * 
   * @param id - The UUID of the user
   * @returns The complete User record from the database, or null if not found
   */
  public async findUserById(id: string): Promise<User | null> {
    return prisma.user.findUnique({
      where: { id },
    });
  }

  /**
   * Inserts a new user record into the database.
   * CRITICAL: The data passed here must already contain the heavily hashed password, 
   * not the plain text. The Service layer is responsible for the hashing.
   * 
   * @param data - The Prisma-typed input object containing email, hash, and optional fields
   * @returns The newly created User record
   */
  public async createUser(data: Prisma.UserCreateInput): Promise<User> {
    return prisma.user.create({
      data,
    });
  }

  /**
   * SCALABILITY HELPER: Updates user information.
   * Prepared for future implementations like 'update profile', 'change password', 
   * or 'record last login timestamp'.
   * 
   * @param id - The UUID of the user to update
   * @param data - The fields to update
   */
  public async updateUser(id: string, data: Prisma.UserUpdateInput): Promise<User> {
    return prisma.user.update({
      where: { id },
      data,
    });
  }
}
