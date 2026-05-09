import bcrypt from 'bcrypt';

// The cost factor controls how much time is needed to calculate a single bcrypt hash.
// Higher is more secure against brute-force attacks but slower to compute.
// 12 is currently the industry-standard balance for modern production backends.
const SALT_ROUNDS = 12;

export class PasswordUtil {
  /**
   * Hashes a plain text password using bcrypt.
   * @param password - The plain text password provided by the user
   * @returns A promise that resolves to the safely hashed password string
   */
  public static async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    return bcrypt.hash(password, salt);
  }

  /**
   * Securely compares a plain text password attempt against a stored bcrypt hash.
   * @param password - The plain text password attempt from the login request
   * @param hash - The hashed password stored in the database
   * @returns A promise that resolves to a boolean indicating if the password is correct
   */
  public static async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
}
