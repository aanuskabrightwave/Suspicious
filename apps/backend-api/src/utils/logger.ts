// SHIVAM WORK AREA
/**
 * apps/backend-api/src/utils/logger.ts
 */
export const logger = {
  info: (msg: string, meta?: any) => {
    console.log(JSON.stringify({ level: 'info', msg, ...meta, timestamp: new Date().toISOString() }));
  },
  error: (msg: string, meta?: any) => {
    console.error(JSON.stringify({ level: 'error', msg, ...meta, timestamp: new Date().toISOString() }));
  },
  warn: (msg: string, meta?: any) => {
    console.warn(JSON.stringify({ level: 'warn', msg, ...meta, timestamp: new Date().toISOString() }));
  },
};