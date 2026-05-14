import path from 'path';
import dotenv from 'dotenv';

// Load environment variables from .env file
// We use path.resolve to ensure the .env is loaded relative to this file's location,
// and set override: true to ensure local .env values take precedence over shell env.
dotenv.config({ 
  path: path.resolve(__dirname, '../../.env'),
  override: true 
});

// Define the expected structure of our environment variables
interface EnvConfig {
  PORT: number;
  NODE_ENV: string;
  DATABASE_URL: string;
  JWT_SECRET: string;
  REDIS_URL: string;
}

// Function to validate and load the environment variables
const getEnvConfig = (): EnvConfig => {
  const {
    PORT = '5000',
    NODE_ENV = 'development',
    DATABASE_URL,
    JWT_SECRET,
    REDIS_URL,
  } = process.env;

  // Validate required variables
  const missingVariables: string[] = [];

  if (!DATABASE_URL) missingVariables.push('DATABASE_URL');
  if (!JWT_SECRET) missingVariables.push('JWT_SECRET');
  if (!REDIS_URL) missingVariables.push('REDIS_URL');

  // Throw an error immediately if configuration is invalid
  // This prevents the application from starting in a broken state
  if (missingVariables.length > 0) {
    throw new Error(`Missing required environment variables: ${missingVariables.join(', ')}`);
  }

  return {
    PORT: parseInt(PORT, 10),
    NODE_ENV,
    DATABASE_URL: DATABASE_URL as string,
    JWT_SECRET: JWT_SECRET as string,
    REDIS_URL: REDIS_URL as string,
  };
};

// Export a singleton configuration object that is strictly typed and validated
export const env = getEnvConfig();