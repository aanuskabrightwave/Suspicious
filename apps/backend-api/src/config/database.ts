import { PrismaClient } from '@prisma/client';
import { env } from './env';

// We declare a global variable so that in development, we don't exhaust
// database connections by repeatedly instantiating PrismaClient on hot reloads.
declare global {
  var prisma: PrismaClient | undefined;
}

export const prisma = global.prisma || new PrismaClient({
  log: env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
});

if (env.NODE_ENV !== 'production') {
  global.prisma = prisma;
}

export default prisma;
